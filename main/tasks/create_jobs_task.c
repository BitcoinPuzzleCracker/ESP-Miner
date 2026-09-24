#include <sys/time.h>
#include <limits.h>
#include <inttypes.h>

#include "global_state.h"
#include "esp_log.h"
#include "esp_system.h"
#include "mining.h"
#include "miner_job.h"
#include "string.h"
#include "esp_timer.h"

#include "asic.h"
#include "system.h"
#include "esp_heap_caps.h"
#include "utils.h"

static const char *TAG = "create_jobs_task";

#define MAX_EXTRANONCE2_LEN 32
#define MAX_EXTRANONCE2_STR (MAX_EXTRANONCE2_LEN * 2 + 1)

/* ------------------------------------------------------------------ */
/* NTime rolling configuratie                                          */
/* ------------------------------------------------------------------ */
#define NTIME_MAX_ROLL_SECONDS   7200   /* pool-limiet: +2 uur */

/* ------------------------------------------------------------------ */
/* Job generatie                                                       */
/* ------------------------------------------------------------------ */
static void generate_work_from_miner_job(GlobalState *GLOBAL_STATE,
                                         const miner_job_t *job,
                                         uint64_t extranonce_2,
                                         uint32_t current_version,
                                         int32_t  ntime_offset)
{
    if (!job) return;

    bm_job *next_job = malloc(sizeof(bm_job));
    if (next_job == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for new job");
        return;
    }

    uint32_t version_mask = job->version_mask;
    double   job_diff     = job->pool_diff;

    uint8_t merkle_root[32];
    char    extranonce_2_str[MAX_EXTRANONCE2_STR] = "";

    uint32_t effective_version = job->version;
    if (!GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling
        && !miner_job_is_rollable(job)) {
        effective_version = current_version;
    }

    if (job->type == JOB_TYPE_SV2_STANDARD) {
        memcpy(merkle_root, job->merkle_root, 32);
    } else {
        size_t e2_len = job->extranonce2_len;
        if (e2_len > MAX_EXTRANONCE2_LEN) {
            ESP_LOGE(TAG, "extranonce_2_len %u exceeds maximum %d, skipping job",
                     (unsigned)e2_len, MAX_EXTRANONCE2_LEN);
            free(next_job);
            return;
        }

        uint8_t extranonce_2_bin[MAX_EXTRANONCE2_LEN] = {0};
        size_t  copy_len = (e2_len < sizeof(uint64_t)) ? e2_len : sizeof(uint64_t);
        if (e2_len > 0) {
            memcpy(extranonce_2_bin, &extranonce_2, copy_len);
            bin2hex(extranonce_2_bin, e2_len,
                    extranonce_2_str, sizeof(extranonce_2_str));
        }

        uint8_t coinbase_tx_hash[32];
        calculate_coinbase_tx_hash_bin(job->coinbase_prefix, job->coinbase_prefix_len,
                                       job->extranonce1,      job->extranonce1_len,
                                       extranonce_2_bin,      e2_len,
                                       job->coinbase_suffix,  job->coinbase_suffix_len,
                                       coinbase_tx_hash);

        calculate_merkle_root_hash(coinbase_tx_hash,
                                   (const uint8_t (*)[32])job->merkle_path,
                                   job->merkle_path_count, merkle_root);
    }

    construct_bm_job_from_miner_job(job, effective_version, merkle_root,
                                    version_mask, job_diff,
                                    GLOBAL_STATE->DEVICE_CONFIG.family.asic.software_midstates,
                                    next_job);

    /* NTime rolling override */
    next_job->ntime = job->ntime + (uint32_t)ntime_offset;

    next_job->jobid       = strdup(job->job_id);
    next_job->extranonce2 = strdup(extranonce_2_str);

    if (next_job->jobid == NULL || next_job->extranonce2 == NULL) {
        ESP_LOGE(TAG, "Failed to allocate job metadata");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized, skipping job send");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}

/* ------------------------------------------------------------------ */
/* Hoofdtaak                                                           */
/* ------------------------------------------------------------------ */
void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    uint32_t current_version_mask = 0;
    miner_job_t *current_work     = NULL;
    bool     current_work_sent    = false;
    uint64_t extranonce_2         = 0;
    uint32_t current_version      = 0;

    /* Onze eigen kopie van de ntime die we NU minen — pool-slot mag
     * hergebruikt worden zonder dat wij dat merken. */
    uint32_t current_job_ntime    = 0;

    /* NTime rolling state */
    int32_t  ntime_offset        = 0;
    uint32_t version_rolls_done  = 0;
    uint32_t version_rolls_total = 1;

    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms", timeout_ms);
    ESP_LOGI(TAG, "ASIC Ready! (ntime rolling up to +%d s)", NTIME_MAX_ROLL_SECONDS);
    ESP_LOGI(TAG, "Mode: keep rolling (version + ntime) until NEW BLOCK arrives");

    while (1) {
        uint64_t start_time   = esp_timer_get_time();
        uint32_t slot_notify  = 0;
        TickType_t wait_ticks = (timeout_ms > 0) ? pdMS_TO_TICKS(timeout_ms) : 0;

        BaseType_t notified = xTaskNotifyWait(0, ULONG_MAX, &slot_notify, wait_ticks);
        timeout_ms -= (esp_timer_get_time() - start_time) / 1000;

        if (notified == pdTRUE) {
            miner_job_t *new_work = miner_job_get_slot((size_t)slot_notify);

            /* ---------------------------------------------------------
             * REFRESH (clean_jobs == false):
             *   Pool stuurt nieuwe txns/fees en een nieuwe ntime, maar
             *   het blok is hetzelfde. Wij NEGEREN deze volledig en
             *   blijven doorrollen op ONZE huidige work.
             *
             *   Alleen een ECHT nieuw blok (clean_jobs == true) mag
             *   ons resetten.
             * --------------------------------------------------------- */
            if (!new_work->clean_jobs && current_work != NULL) {
                ESP_LOGI(TAG, "Refresh ignored (slot %lu, job %s) — staying on our roll",
                         (unsigned long)slot_notify, new_work->job_id);
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            /* ---------------------------------------------------------
             * NIEUW BLOK (clean_jobs == true):
             *   Volledige reset van alle rolling-state.
             * --------------------------------------------------------- */
            ESP_LOGI(TAG, "*** NEW BLOCK *** (slot %lu) %s (type %d)",
                     (unsigned long)slot_notify, new_work->job_id, new_work->type);

            current_work      = new_work;
            current_job_ntime = new_work->ntime;

            GLOBAL_STATE->active_job_slot_idx =
                (uint8_t)(slot_notify % MINER_JOB_POOL_SIZE);

            current_work_sent = false;
            current_version   = new_work->version;
            extranonce_2      = 0;

            /* Reset alle rolling-state */
            ntime_offset       = 0;
            version_rolls_done = 0;

            /* Bereken version rolling ruimte */
            if (!GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling) {
                uint32_t mask = (new_work->version_mask != 0)
                                ? new_work->version_mask
                                : BIP320_VERSION_ROLLING_MASK;

                int bits = __builtin_popcount(mask);
                version_rolls_total = (bits >= 32) ? 0xFFFFFFFFu : (1u << bits);

                ESP_LOGI(TAG, "Version rolling: mask=0x%08" PRIx32
                              ", %d bits -> %" PRIu32 " combinations",
                         mask, bits, version_rolls_total);
            }

            if (new_work->version_mask != current_version_mask
                && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Set chip version rolls %i",
                         (int)(new_work->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, new_work->version_mask);
                current_version_mask = new_work->version_mask;
            }
        } else {
            /* Timeout — geen notify, ga gewoon door met onze eigen roll */
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }

            /* Hardware rolling: 1x zenden is genoeg */
            if (current_work_sent
                && GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling) {
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            /* Volledige werkruimte op? -> wacht op nieuw blok */
            if (current_work_sent
                && !GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling
                && version_rolls_done >= version_rolls_total
                && ntime_offset > NTIME_MAX_ROLL_SECONDS) {
                vTaskDelay(pdMS_TO_TICKS(100));
                continue;
            }
        }

        /* ---------------- Werk genereren en zenden ---------------- */
        generate_work_from_miner_job(GLOBAL_STATE, current_work,
                                     extranonce_2, current_version,
                                     ntime_offset);

        if (!current_work_sent) {
            SYSTEM_decode_and_apply_coinbase(GLOBAL_STATE, current_work);
        }
        current_work_sent = true;

        /* ---------------- Version + NTime rolling ---------------- */
        if (!GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling) {
            uint32_t mask = (current_work->version_mask != 0)
                            ? current_work->version_mask
                            : BIP320_VERSION_ROLLING_MASK;
            uint8_t midstates =
                GLOBAL_STATE->DEVICE_CONFIG.family.asic.software_midstates;

            if (version_rolls_done >= version_rolls_total) {
                /* Versie-ruimte op -> ntime +1, versie opnieuw beginnen */
                ntime_offset++;
                current_version    = current_work->version;
                version_rolls_done = 0;

                ESP_LOGI(TAG, "Version space exhausted, ntime+1 -> offset %" PRId32
                              " (job %s)", ntime_offset, current_work->job_id);

                if (ntime_offset > NTIME_MAX_ROLL_SECONDS) {
                    ESP_LOGW(TAG, "NTime range exhausted, waiting for new block");
                    vTaskDelay(pdMS_TO_TICKS(100));
                    continue;
                }
            } else {
                for (int i = 0; i < midstates; i++) {
                    current_version = increment_bitmask(current_version, mask);
                    version_rolls_done++;

                    if (version_rolls_done >= version_rolls_total) {
                        break;
                    }
                }
            }
        }

        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}
