#include <sys/time.h>
#include <limits.h>
#include <inttypes.h>

#include "global_state.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
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

static void generate_work_from_miner_job(GlobalState *GLOBAL_STATE, const miner_job_t *job, uint32_t current_version)
{
    if (!job) return;

    bm_job *next_job = malloc(sizeof(bm_job));
    if (next_job == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for new job");
        return;
    }

    uint32_t version_mask = job->version_mask;
    double job_diff = job->pool_diff;

    uint8_t merkle_root[32];
    char extranonce_2_str[MAX_EXTRANONCE2_STR] = "";

    uint32_t effective_version = job->version;
    if (!GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling && !miner_job_is_rollable(job)) {
        effective_version = current_version;
    }

    if (job->type == JOB_TYPE_SV2_STANDARD) {
        memcpy(merkle_root, job->merkle_root, 32);
    } else {
        size_t e2_len = job->extranonce2_len;
        if (e2_len > MAX_EXTRANONCE2_LEN) {
            ESP_LOGE(TAG, "extranonce_2_len %u exceeds maximum %d, skipping job", (unsigned)e2_len, MAX_EXTRANONCE2_LEN);
            free(next_job);
            return;
        }

        uint8_t extranonce_2_bin[MAX_EXTRANONCE2_LEN] = {0};
        if (e2_len > 0) {
            for (size_t i = 0; i < e2_len; i += 4) {
                uint32_t rand_val = esp_random();
                size_t chunk = (e2_len - i < 4) ? (e2_len - i) : 4;
                for (size_t j = 0; j < chunk; j++) {
                    extranonce_2_bin[i + j] = (rand_val >> (8 * j)) & 0xFF;
                }
            }
            bin2hex(extranonce_2_bin, e2_len, extranonce_2_str, sizeof(extranonce_2_str));
        }

        uint8_t coinbase_tx_hash[32];
        calculate_coinbase_tx_hash_bin(job->coinbase_prefix, job->coinbase_prefix_len,
                                       job->extranonce1, job->extranonce1_len,
                                       extranonce_2_bin, e2_len,
                                       job->coinbase_suffix, job->coinbase_suffix_len,
                                       coinbase_tx_hash);

        calculate_merkle_root_hash(coinbase_tx_hash,
                                   (const uint8_t (*)[32])job->merkle_path,
                                   job->merkle_path_count, merkle_root);
    }

    construct_bm_job_from_miner_job(job, effective_version, merkle_root, version_mask, job_diff, GLOBAL_STATE->DEVICE_CONFIG.family.asic.software_midstates, next_job);
    next_job->jobid = strdup(job->job_id);
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

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    uint32_t current_version_mask = 0;
    miner_job_t *current_work = NULL;
    bool current_work_sent = false;
    uint32_t current_version = 0;
    
    // Bewaar de vorige prevhash / block hash om een echt nieuw blok te detecteren
    char last_prevhash[64] = {0};
    bool has_last_prevhash = false;

    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms", timeout_ms);
    ESP_LOGI(TAG, "ASIC Ready!");

    while (1) {
        uint64_t start_time = esp_timer_get_time();
        uint32_t slot_notify = 0;
        TickType_t wait_ticks = (timeout_ms > 0) ? pdMS_TO_TICKS(timeout_ms) : 0;
        BaseType_t notified = xTaskNotifyWait(0, ULONG_MAX, &slot_notify, wait_ticks);
        timeout_ms -= (esp_timer_get_time() - start_time) / 1000;

        if (notified == pdTRUE) {
            miner_job_t *new_work = miner_job_get_slot((size_t)slot_notify);
            
            // Controleer of de prevhash (blok hash van vorig blok) daadwerkelijk is veranderd.
            // Als de pool alleen de job_id verandert maar de prevhash is hetzelfde, is het GEEN nieuw blok.
            bool is_new_block = false;
            if (new_work->prevhash) {
                if (!has_last_prevhash || strcmp(new_work->prevhash, last_prevhash) != 0) {
                    is_new_block = true;
                    strncpy(last_prevhash, new_work->prevhash, sizeof(last_prevhash) - 1);
                    has_last_prevhash = true;
                }
            } else {
                // Fallback als prevhash niet direct beschikbaar is: vergelijk op basis van clean_jobs vlag
                if (new_work->clean_jobs) {
                    is_new_block = true;
                }
            }

            if (is_new_block) {
                ESP_LOGI(TAG, ">>> ECHT NIEUW BLOK ONTVANGEN! Versie en rolling worden gereset.");
                current_work = new_work;
                current_version = new_work->version;
                current_work_sent = false;
            } else {
                // Tussentijdse job van pool genegeerd qua reset: we rollen stug door op de huidige template!
                ESP_LOGI(TAG, "Tussentijdse job-update genegeerd voor reset, doorrollen op huidige template.");
                // We updaten wel de pointer voor eventuele pointers, maar behouden de lopende current_version!
                current_work = new_work;
            }

            GLOBAL_STATE->active_job_slot_idx = (uint8_t)(slot_notify % MINER_JOB_POOL_SIZE);

            if (new_work->version_mask != current_version_mask && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Set chip version rolls %i", (int)(new_work->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, new_work->version_mask);
                current_version_mask = new_work->version_mask;
            }

            if (!current_work->clean_jobs && current_work_sent && !is_new_block) {
                continue;
            }
        } else {
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }
        }

        generate_work_from_miner_job(GLOBAL_STATE, current_work, current_version);
        if (!current_work_sent) {
            SYSTEM_decode_and_apply_coinbase(GLOBAL_STATE, current_work);
        }
        current_work_sent = true;

        // Blijf onverstoorbaar doorrollen binnen het masker
        uint32_t mask = (current_work->version_mask != 0) ? current_work->version_mask : BIP320_VERSION_ROLLING_MASK;
        uint8_t midstates = GLOBAL_STATE->DEVICE_CONFIG.family.asic.software_midstates;
        if (midstates == 0) midstates = 1;

        for (int i = 0; i < midstates; i++) {
            current_version = increment_bitmask(current_version, mask);
        }

        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}
