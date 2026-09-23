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

// Debounce: negeer duplicate-meldingen gedurende 2 seconden na een roll
#define EXTRANONCE_ROLL_DEBOUNCE_US (2ULL * 1000 * 1000)

// Globaal: wordt gezet door stratum_v1.c als een "Duplicate" binnenkomt
volatile bool g_extranonce2_roll_requested = false;

static void generate_work_from_miner_job(GlobalState *GLOBAL_STATE, const miner_job_t *job, uint64_t extranonce_2, uint32_t current_version)
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
        size_t copy_len = (e2_len < sizeof(uint64_t)) ? e2_len : sizeof(uint64_t);
        if (e2_len > 0) {
            memcpy(extranonce_2_bin, &extranonce_2, copy_len);
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
    bool coinbase_needs_decode = true;      // alleen bij nieuwe pool-job
    uint64_t extranonce_2 = 0;
    uint32_t current_version = 0;
    uint64_t last_roll_us = 0;               // debounce-timestamp
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

            // Refresh-notifies negeren we volledig. Ronde 2 en verder komen
            // door duplicate-detectie, niet door refresh.
            if (!new_work->clean_jobs && current_work != NULL) {
                ESP_LOGI(TAG, "Ignoring refresh notify (slot %lu, job %s), staying on %s",
                         (unsigned long)slot_notify, new_work->job_id, current_work->job_id);
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            ESP_LOGI(TAG, "New Work Activated (slot %lu) %s (type %d) clean_jobs=%d",
                     (unsigned long)slot_notify, new_work->job_id, new_work->type,
                     (int)new_work->clean_jobs);
            current_work = new_work;
            GLOBAL_STATE->active_job_slot_idx = (uint8_t)(slot_notify % MINER_JOB_POOL_SIZE);
            current_work_sent = false;
            coinbase_needs_decode = true;
            current_version = new_work->version;

            if (new_work->version_mask != current_version_mask && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Set chip version rolls %i", (int)(new_work->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, new_work->version_mask);
                current_version_mask = new_work->version_mask;
            }

            // Reset ronde
            extranonce_2 = 0;
            last_roll_us = esp_timer_get_time();
            g_extranonce2_roll_requested = false;
            ESP_LOGI(TAG, "Extranonce2 reset -> 0");
        } else {
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }

            // ----- Duplicate-detectie: ronde voorbij, rol extranonce2 -----
            if (g_extranonce2_roll_requested) {
                uint64_t now_us = esp_timer_get_time();
                if (now_us - last_roll_us >= EXTRANONCE_ROLL_DEBOUNCE_US) {
                    extranonce_2++;
                    last_roll_us = now_us;
                    current_work_sent = false;
                    coinbase_needs_decode = false;   // coinbase blijft hetzelfde, alleen extranonce2 in hash verschilt
                    ESP_LOGI(TAG, "Duplicate detected -> extranonce2 rolled to %" PRIu64, extranonce_2);
                } else {
                    ESP_LOGD(TAG, "Duplicate debounced (last roll %" PRIu64 " ms ago)",
                             (now_us - last_roll_us) / 1000);
                }
                g_extranonce2_roll_requested = false;
            }

            // Werk verstuurd en niks aan de hand? Blijf wachten.
            if (current_work_sent
                && GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling
                && !g_extranonce2_roll_requested) {
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }
        }

        generate_work_from_miner_job(GLOBAL_STATE, current_work, extranonce_2, current_version);
        if (coinbase_needs_decode) {
            SYSTEM_decode_and_apply_coinbase(GLOBAL_STATE, current_work);
            coinbase_needs_decode = false;
        }
        current_work_sent = true;

        if (!GLOBAL_STATE->DEVICE_CONFIG.family.asic.hardware_version_rolling) {
            uint32_t mask = (current_work->version_mask != 0) ? current_work->version_mask : BIP320_VERSION_ROLLING_MASK;
            uint8_t midstates = GLOBAL_STATE->DEVICE_CONFIG.family.asic.software_midstates;
            for (int i = 0; i < midstates; i++) {
                current_version = increment_bitmask(current_version, mask);
            }
        }
        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}
