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

    if (job->type == JOB_TYPE_SV2_STANDARD) {
        memcpy(merkle_root, job->merkle_root, 32);
    } else {
        size_t e2_len = job->extranonce2_len;
        if (e2_len > MAX_EXTRANONCE2_LEN) {
            ESP_LOGE(TAG, "extranonce_2_len %u exceeds maximum %d, skipping job", (unsigned)e2_len, MAX_EXTRANONCE2_LEN);
            free(next_job);
            return;
        }

        // Extranonce 2 vast op nullen zetten (geen CPU-belasting voor de ESP32)
        if (e2_len > 0) {
            size_t hex_len = e2_len * 2;
            if (hex_len >= MAX_EXTRANONCE2_STR) hex_len = MAX_EXTRANONCE2_STR - 1;
            memset(extranonce_2_str, '0', hex_len);
            extranonce_2_str[hex_len] = '\0';
        }

        uint8_t extranonce_2_bin[MAX_EXTRANONCE2_LEN] = {0};
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
    uint32_t current_version = 0;

    ESP_LOGI(TAG, "ASIC Ready with Hardware Version Rolling & Static Extranonce 2!");

    while (1) {
        uint32_t slot_notify = 0;
        // Wacht tot de pool een nieuwe job meldt. De BM1370 doet de rest via hardware version rolling.
        BaseType_t notified = xTaskNotifyWait(0, ULONG_MAX, &slot_notify, portMAX_DELAY);

        if (notified == pdTRUE) {
            miner_job_t *new_work = miner_job_get_slot((size_t)slot_notify);
            if (new_work == NULL) continue;

            ESP_LOGI(TAG, "New Work Activated (slot %lu) %s (type %d)", (unsigned long)slot_notify, new_work->job_id, new_work->type);
            current_work = new_work;
            GLOBAL_STATE->active_job_slot_idx = (uint8_t)(slot_notify % MINER_JOB_POOL_SIZE);
            current_version = new_work->version;

            if (new_work->version_mask != current_version_mask && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Set chip version rolls %i", (int)(new_work->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, new_work->version_mask);
                current_version_mask = new_work->version_mask;
            }

            // Stuur de job eenmalig naar de ASIC. De chip rolt de version bits nu zelf in hardware.
            generate_work_from_miner_job(GLOBAL_STATE, current_work, current_version);
            SYSTEM_decode_and_apply_coinbase(GLOBAL_STATE, current_work);
        }
    }
}
