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

/* Bij hardware version rolling kan de firmware niet weten wanneer de
 * ASIC zijn version-ruimte heeft uitgeput. We bumpen daarom periodiek
 * de ntime om verse hashes te forceren. */
#define NTIME_BUMP_INTERVAL_S    300    /* 5 minuten */

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

    /* NTime rolling override — ALTIJD toepassen, ongeacht HW/SW version rolling */
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

    /* Onze eigen kopie van de ntime die we NU minen */
    uint32_t current_job_ntime    = 0;

    /* NTime rolling state */
    int32_t  ntime_offset        = 0;
    uint32_t version_rolls_done  = 0;
    uint32_t version_rolls_total = 1;

    /* Time-based ntime bump (voor hardware version rolling) */
    uint64_t last_ntime_bump_us  = 0;

    const bool hw_version_rolling =
        GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling;

    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms", timeout_ms);
    ESP_LOGI(TAG, "ASIC Ready! (ntime rolling up to +%d s)", NTIME_MAX_ROLL_SECONDS);
    ESP_LOGI(TAG, "Mode: %s version rolling + software ntime rolling",
             hw_version_rolling ? "hardware" : "software");

    if (hw_version_rolling) {
        ESP_LOGI(TAG, "NTime bump interval: %d s (hardware version rolling detected)",
                 NTIME_BUMP_INTERVAL_S);
    }

    while (1) {
        uint64_t start_time   = esp_timer_get_time();
        uint32_t slot_notify  = 0;
        TickType_t wait_ticks = (timeout_ms > 0) ? pdMS_TO_TICKS(timeout_ms) : 0;

        BaseType_t notified = xTaskNotifyWait(0, ULONG_MAX, &slot_notify, wait_ticks);
        timeout_ms -= (esp_timer_get_time() - start_time) / 1000;

        if (notified == pdTRUE) {
            miner_job_t *new_work = miner_job_get_slot((size_t)slot_notify);

            /* ---------------------------------------------------------
             * REFRESH: negeren, blijf op eigen roll
             * --------------------------------------------------------- */
            if (!new_work->clean_jobs && current_work != NULL) {
                ESP_LOGD(TAG, "Refresh ignored (slot %lu, job %s)",
                         (unsigned long)slot_notify, new_work->job_id);
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            /* ---------------------------------------------------------
             * NIEUW BLOK: volledige reset
             * --------------------------------------------------------- */
            ESP_LOGI(TAG, "*** NEW BLOCK *** (slot %lu) %s (type %d)",
                     (unsigned long)slot_notify, new_work->job_id, new_work->type);

            current_work      = new_work;
            current_job_ntime = new_work->ntime;

            GLOBAL_STATE->active_job_slot_idx =
                (uint8_t)(slot_notify % MINER_JOB_POOL_SIZE);

            current_work_sent    = false;
            current_version      = new_work->version;
            extranonce_2         = 0;

            /* Reset rolling state */
            ntime_offset         = 0;
            version_rolls_done   = 0;
            last_ntime_bump_us   = esp_timer_get_time();

            /* Bereken version rolling ruimte (alleen relevant voor SW rolling) */
            if (!hw_version_rolling) {
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
            /* Timeout */
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }

            /* ---------------------------------------------------------
             * HARDWARE VERSION ROLLING:
             *   De ASIC rolt zelf de versie-bits. Wij kunnen niet weten
             *   wanneer hij klaar is. Daarom bumpen we periodiek de ntime
             *   om verse hashes te forceren en duplicates te voorkomen.
             * --------------------------------------------------------- */
            if (hw_version_rolling) {
                if (!current_work_sent) {
                    /* Nog niets verzonden — valt door naar send hieronder */
                } else {
                    uint64_t elapsed_s =
                        (esp_timer_get_time() - last_ntime_bump_us) / 1000000ULL;

                    if (elapsed_s >= NTIME_BUMP_INTERVAL_S) {
                        if (ntime_offset < NTIME_MAX_ROLL_SECONDS) {
                            ntime_offset++;
                            current_work_sent  = false;
                            last_ntime_bump_us = esp_timer_get_time();

                            ESP_LOGI(TAG, "NTime bump (HW-rolling) -> offset %" PRId32
                                          " (job %s)",
                                     ntime_offset, current_work->job_id);
                        } else {
                            /* Uitgeput — wacht op nieuw blok */
                            ESP_LOGW(TAG, "NTime range exhausted, waiting for new block");
                            vTaskDelay(pdMS_TO_TICKS(100));
                            continue;
                        }
                    } else {
                        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                        continue;
                    }
                }
            } else {
                /* -----------------------------------------------------
                 * SOFTWARE VERSION ROLLING:
                 *   Traditionele aanpak: version-ruimte uitputten,
                 *   dan ntime+1, herhaal tot NTIME_MAX_ROLL_SECONDS.
                 * ----------------------------------------------------- */
                if (current_work_sent
                    && version_rolls_done >= version_rolls_total
                    && ntime_offset > NTIME_MAX_ROLL_SECONDS) {
                    vTaskDelay(pdMS_TO_TICKS(100));
                    continue;
                }
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

        /* ---------------- Software version rolling ---------------- */
        if (!hw_version_rolling) {
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
