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

#define TARGET_JOB_LIFETIME_MS 10000 // Hedeflenen 10 saniyelik pencere

static void generate_work_from_miner_job(GlobalState *GLOBAL_STATE,
                                         const miner_job_t *job,
                                         uint32_t current_version)
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
    char    extranonce_2_str[MAX_EXTRANONCE2_STR] = "00000000"; // Extranonce2 sabit 0

    uint32_t effective_version = current_version;

    if (job->type == JOB_TYPE_SV2_STANDARD) {
        memcpy(merkle_root, job->merkle_root, 32);
    } else {
        uint8_t extranonce_2_bin[MAX_EXTRANONCE2_LEN] = {0};
        uint8_t coinbase_tx_hash[32];
        
        calculate_coinbase_tx_hash_bin(job->coinbase_prefix, job->coinbase_prefix_len,
                                       job->extranonce1,      job->extranonce1_len,
                                       extranonce_2_bin,      0,
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

    next_job->ntime       = job->ntime;
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

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    uint32_t current_version_mask = 0;
    miner_job_t *current_work     = NULL;
    bool     current_work_sent    = false;
    uint32_t current_version      = 0;

    uint32_t version_rolls_done   = 0;
    uint32_t version_rolls_total  = 1;
    uint32_t steps_per_interval   = 1;

    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms | Safe Step Rolling Active", timeout_ms);

    while (1) {
        uint64_t start_time   = esp_timer_get_time();
        uint32_t slot_notify  = 0;
        TickType_t wait_ticks = (timeout_ms > 0) ? pdMS_TO_TICKS(timeout_ms) : 0;

        BaseType_t notified = xTaskNotifyWait(0, ULONG_MAX, &slot_notify, wait_ticks);
        timeout_ms -= (esp_timer_get_time() - start_time) / 1000;

        if (notified == pdTRUE) {
            miner_job_t *new_work = miner_job_get_slot((size_t)slot_notify);

            if (!new_work->clean_jobs && current_work != NULL) {
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            ESP_LOGI(TAG, "*** YENİ İŞ GELDİ *** (slot %lu) %s", (unsigned long)slot_notify, new_work->job_id);

            current_work        = new_work;
            current_version     = new_work->version;
            current_work_sent   = false;
            version_rolls_done  = 0;

            uint32_t mask = (new_work->version_mask != 0) ? new_work->version_mask : BIP320_VERSION_ROLLING_MASK;
            int bits = __builtin_popcount(mask);
            version_rolls_total = (bits >= 32) ? 0xFFFFFFFFu : (1u << bits);

            int ticks_in_10s = TARGET_JOB_LIFETIME_MS / (timeout_ms > 0 ? timeout_ms : 500);
            steps_per_interval = version_rolls_total / (ticks_in_10s > 0 ? ticks_in_10s : 1);
            if (steps_per_interval == 0) steps_per_interval = 1;

            ESP_LOGI(TAG, "Versiyon Uzayı: %lu kombinasyon, Her adım: %lu", 
                     (unsigned long)version_rolls_total, (unsigned long)steps_per_interval);

            if (new_work->version_mask != current_version_mask && GLOBAL_STATE->ASIC_initalized) {
                ASIC_set_version_mask(GLOBAL_STATE, new_work->version_mask);
                current_version_mask = new_work->version_mask;
            }
        } else {
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }

            // GÜVENLİK KONTROLÜ: Versiyon uzayı bittiyse duplicate share atmamak için beklet
            if (version_rolls_done >= version_rolls_total) {
                ESP_LOGD(TAG, "Versiyon aralığı tamamlandı, yeni iş bekleniyor...");
                vTaskDelay(pdMS_TO_TICKS(250));
                continue;
            }
        }

        // Eğer uzay dolduysa iş göndermeyi atla
        if (version_rolls_done < version_rolls_total) {
            generate_work_from_miner_job(GLOBAL_STATE, current_work, current_version);

            if (!current_work_sent) {
                SYSTEM_decode_and_apply_coinbase(GLOBAL_STATE, current_work);
            }
            current_work_sent = true;

            // Versiyonu bir sonraki adım için ilerlet
            uint32_t mask = (current_work->version_mask != 0) ? current_work->version_mask : BIP320_VERSION_ROLLING_MASK;
            uint8_t midstates = GLOBAL_STATE->DEVICE_CONFIG.family.asic.software_midstates;

            for (uint32_t s = 0; s < steps_per_interval; s++) {
                for (int i = 0; i < midstates; i++) {
                    current_version = increment_bitmask(current_version, mask);
                    version_rolls_done++;
                    if (version_rolls_done >= version_rolls_total) break;
                }
                if (version_rolls_done >= version_rolls_total) break;
            }
        }

        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}
