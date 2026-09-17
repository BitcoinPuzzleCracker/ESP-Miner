#include <sys/time.h>
#include <limits.h>

#include "work_queue.h"
#include "global_state.h"
#include "esp_log.h"
#include "esp_system.h"
#include "mining.h"
#include "string.h"
#include "esp_timer.h"

#include "asic.h"
#include "system.h"
#include "esp_heap_caps.h"
#include "sv2_protocol.h"
#include "stratum_api.h"
#include "stratum_v2_task.h"
#include "utils.h"

static const char *TAG = "create_jobs_task";

#define MAX_EXTRANONCE2_LEN 32
#define MAX_EXTRANONCE2_STR (MAX_EXTRANONCE2_LEN * 2 + 1)

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, double difficulty);
static void generate_work_sv2(GlobalState *GLOBAL_STATE, sv2_job_t *job, double difficulty);
static void generate_work_sv2_ext(GlobalState *GLOBAL_STATE, sv2_ext_job_t *job, double difficulty);
static void populate_midstates(uint32_t base_version, const uint8_t *prev_hash, const uint8_t *merkle_root, uint32_t version_mask, bm_job *next_job);

// Free a work item using the correct free function for the protocol it was created under[span_1](start_span)[span_1](end_span)
static void free_work_item(GlobalState *GLOBAL_STATE, void *work, stratum_protocol_t protocol)
{
    if (!work) return;
    if (protocol == STRATUM_PROTOCOL_V2) {
        if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
            sv2_ext_job_free((sv2_ext_job_t *)work);
        } else {
            free(work);  // sv2_job_t is flat[span_2](start_span)[span_2](end_span)
        }
    } else {
        STRATUM_V1_free_mining_notify(work);
    }
}

// Ortak midstate ve versiyon maskesi hesaplama fonksiyonu (Kod tekrarı önlendi)
static void populate_midstates(uint32_t base_version, const uint8_t *prev_hash, const uint8_t *merkle_root, uint32_t version_mask, bm_job *next_job)
{
    next_job->version = base_version;
    reverse_32bit_words(merkle_root, next_job->merkle_root);
    reverse_32bit_words(prev_hash, next_job->prev_block_hash);

    uint8_t midstate_data[64];
    memcpy(midstate_data, &base_version, 4);
    memcpy(midstate_data + 4, prev_hash, 32);
    memcpy(midstate_data + 36, merkle_root, 28);

    uint8_t midstate[32];
    midstate_sha256_bin(midstate_data, 64, midstate);
    reverse_32bit_words(midstate, next_job->midstate);

    if (version_mask != 0) {
        uint32_t rolled_version = increment_bitmask(base_version, version_mask);
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, midstate);
        reverse_32bit_words(midstate, next_job->midstate1);

        rolled_version = increment_bitmask(rolled_version, version_mask);
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, midstate);
        reverse_32bit_words(midstate, next_job->midstate2);

        rolled_version = increment_bitmask(rolled_version, version_mask);
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, midstate);
        reverse_32bit_words(midstate, next_job->midstate3);
        next_job->num_midstates = 4;
    } else {
        next_job->num_midstates = 1;
    }
}

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    double difficulty = GLOBAL_STATE->pool_difficulty;
    void *current_work = NULL;
    stratum_protocol_t current_work_protocol = GLOBAL_STATE->stratum_protocol;
    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    static char last_dispatched_job_v1[64] = {0};
    static uint32_t last_dispatched_job_sv2 = UINT32_MAX;

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms", timeout_ms);
    ESP_LOGI(TAG, "ASIC Ready! (Zero-Extranonce2 + BIP320 + Auto-Job-Update)");

    while (1) {
        if (GLOBAL_STATE->reset_extranonce2) {
            GLOBAL_STATE->reset_extranonce2 = false;
        }

        stratum_protocol_t active_protocol = GLOBAL_STATE->stratum_protocol;
        if (active_protocol != current_work_protocol) {
            if (current_work != NULL) {
                ESP_LOGI(TAG, "Protocol switched from %s to %s, discarding current work",
                         current_work_protocol == STRATUM_PROTOCOL_V2 ? STRATUM_V2 : STRATUM_V1,
                         active_protocol == STRATUM_PROTOCOL_V2 ? STRATUM_V2 : STRATUM_V1);
                free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
                current_work = NULL;
            }
            current_work_protocol = active_protocol;
            last_dispatched_job_v1[0] = '\0';
            last_dispatched_job_sv2 = UINT32_MAX;
        }

        uint64_t start_time = esp_timer_get_time();
        void *new_work = queue_dequeue_timeout(&GLOBAL_STATE->stratum_queue, timeout_ms);
        
        // Timeout hesabı ve negatif/sıfır koruması (İyileştirme 2)
        int elapsed_ms = (int)((esp_timer_get_time() - start_time) / 1000);
        timeout_ms -= elapsed_ms;
        if (timeout_ms < 10) {
            timeout_ms = 10;
        }

        if (new_work != NULL) {
            active_protocol = GLOBAL_STATE->stratum_protocol;

            free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
            current_work = NULL;

            if (active_protocol != current_work_protocol) {
                ESP_LOGW(TAG, "Protocol switch detected during dequeue, discarding stale item");
                free(new_work);
                current_work_protocol = active_protocol;
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            current_work = new_work;

            bool is_new_job_id = false;
            bool clean = false;

            if (current_work_protocol == STRATUM_PROTOCOL_V2) {
                if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
                    sv2_ext_job_t *j = (sv2_ext_job_t *)current_work;
                    ESP_LOGI(TAG, "New Work Dequeued SV2 ext job %lu", j->job_id);
                    clean = j->clean_jobs;
                    if (last_dispatched_job_sv2 != j->job_id) {
                        is_new_job_id = true;
                        last_dispatched_job_sv2 = j->job_id;
                    }
                } else {
                    sv2_job_t *j = (sv2_job_t *)current_work;
                    ESP_LOGI(TAG, "New Work Dequeued SV2 job %lu", j->job_id);
                    clean = j->clean_jobs;
                    if (last_dispatched_job_sv2 != j->job_id) {
                        is_new_job_id = true;
                        last_dispatched_job_sv2 = j->job_id;
                    }
                }
            } else {
                mining_notify *j = (mining_notify *)current_work;
                ESP_LOGI(TAG, "New Work Dequeued %s (clean: %s)", j->job_id, j->clean_jobs ? "true" : "false");
                clean = j->clean_jobs;
                if (strcmp(last_dispatched_job_v1, j->job_id) != 0) {
                    is_new_job_id = true;
                    // Güvenli string kopyalama ve sonlandırma (İyileştirme 5)
                    strncpy(last_dispatched_job_v1, j->job_id, sizeof(last_dispatched_job_v1) - 1);
                    last_dispatched_job_v1[sizeof(last_dispatched_job_v1) - 1] = '\0';
                }
            }

            if (GLOBAL_STATE->new_set_mining_difficulty_msg) {
                ESP_LOGI(TAG, "New pool difficulty %.2f", GLOBAL_STATE->pool_difficulty);
                difficulty = GLOBAL_STATE->pool_difficulty;
                GLOBAL_STATE->new_set_mining_difficulty_msg = false;
            }

            if (GLOBAL_STATE->new_stratum_version_rolling_msg && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Set chip version rolls %i", (int)(GLOBAL_STATE->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, GLOBAL_STATE->version_mask);
                GLOBAL_STATE->new_stratum_version_rolling_msg = false;
            }

            if (!is_new_job_id && !clean) {
                continue;
            }

        } else {
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }
            timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
            continue;
        }

        active_protocol = GLOBAL_STATE->stratum_protocol;
        if (active_protocol != current_work_protocol) {
            free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
            current_work = NULL;
            current_work_protocol = active_protocol;
            timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
            continue;
        }

        if (active_protocol == STRATUM_PROTOCOL_V2) {
            if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
                generate_work_sv2_ext(GLOBAL_STATE, (sv2_ext_job_t *)current_work, difficulty);
            } else {
                generate_work_sv2(GLOBAL_STATE, (sv2_job_t *)current_work, difficulty);
            }
        } else {
            generate_work(GLOBAL_STATE, (mining_notify *)current_work, difficulty);
        }

        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, double difficulty)
{
    if (GLOBAL_STATE->extranonce_2_len > MAX_EXTRANONCE2_LEN) {
        ESP_LOGE(TAG, "extranonce_2_len %d exceeds maximum %d, skipping job", GLOBAL_STATE->extranonce_2_len, MAX_EXTRANONCE2_LEN);
        return;
    }

    char extranonce_2_str[MAX_EXTRANONCE2_STR];
    memset(extranonce_2_str, '0', GLOBAL_STATE->extranonce_2_len * 2);
    extranonce_2_str[GLOBAL_STATE->extranonce_2_len * 2] = '\0';

    uint8_t coinbase_tx_hash[32];
    calculate_coinbase_tx_hash(notification->coinbase_1, notification->coinbase_2, GLOBAL_STATE->extranonce_str, extranonce_2_str, coinbase_tx_hash);

    uint8_t merkle_root[32];
    calculate_merkle_root_hash(coinbase_tx_hash, (uint8_t(*)[32])notification->merkle_branches, notification->n_merkle_branches, merkle_root);

    bm_job *next_job = malloc(sizeof(bm_job));
    if (next_job == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for new job");
        return;
    }

    construct_bm_job(notification, merkle_root, GLOBAL_STATE->version_mask, difficulty, next_job);

    next_job->extranonce2 = strdup(extranonce_2_str);
    next_job->jobid = strdup(notification->job_id);
    
    // strdup Null Kontrolü (İyileştirme 1)
    if (!next_job->extranonce2 || !next_job->jobid) {
        ESP_LOGE(TAG, "Failed to allocate memory for job strings (strdup failed)");
        free(next_job->extranonce2);
        free(next_job->jobid);
        free(next_job);
        return;
    }

    next_job->version_mask = GLOBAL_STATE->version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized, skipping job send");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}

static void generate_work_sv2(GlobalState *GLOBAL_STATE, sv2_job_t *sv2_job, double difficulty)
{
    bm_job *next_job = malloc(sizeof(bm_job));
    if (next_job == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for new SV2 job");
        return;
    }

    uint32_t version_mask = GLOBAL_STATE->version_mask;
    next_job->starting_nonce = 0;
    next_job->pool_diff = difficulty;

    // Ortak yardımcı fonksiyon ile midstate üretimi
    populate_midstates(sv2_job->version, sv2_job->prev_hash, sv2_job->merkle_root, version_mask, next_job);

    char jobid_str[16];
    snprintf(jobid_str, sizeof(jobid_str), "%" PRIu32, sv2_job->job_id);
    
    next_job->jobid = strdup(jobid_str);
    next_job->extranonce2 = strdup("");

    // strdup Null Kontrolü (İyileştirme 1)
    if (!next_job->jobid || !next_job->extranonce2) {
        ESP_LOGE(TAG, "Failed to allocate memory for SV2 job strings");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    next_job->version_mask = version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized, skipping SV2 job send");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}

static void generate_work_sv2_ext(GlobalState *GLOBAL_STATE, sv2_ext_job_t *ext_job, double difficulty)
{
    sv2_conn_t *conn = GLOBAL_STATE->sv2_conn;
    if (!conn) return;

    bm_job *next_job = malloc(sizeof(bm_job));
    if (!next_job) {
        ESP_LOGE(TAG, "Failed to allocate memory for SV2 ext job");
        return;
    }

    uint32_t version_mask = GLOBAL_STATE->version_mask;

    uint8_t extranonce_2_len = conn->extranonce_size;
    uint8_t extranonce_2[32];
    memset(extranonce_2, 0, sizeof(extranonce_2));

    uint8_t coinbase_tx_hash[32];
    calculate_coinbase_tx_hash_bin(
        ext_job->coinbase_prefix, ext_job->coinbase_prefix_len,
        conn->extranonce_prefix, conn->extranonce_prefix_len,
        extranonce_2, extranonce_2_len,
        ext_job->coinbase_suffix, ext_job->coinbase_suffix_len,
        coinbase_tx_hash);

    uint8_t merkle_root[32];
    calculate_merkle_root_hash(coinbase_tx_hash,
                               (const uint8_t (*)[32])ext_job->merkle_path,
                               ext_job->merkle_path_count, merkle_root);

    next_job->starting_nonce = 0;
    next_job->pool_diff = difficulty;

    // Ortak yardımcı fonksiyon ile midstate üretimi
    populate_midstates(ext_job->version, ext_job->prev_hash, merkle_root, version_mask, next_job);

    char jobid_str[16];
    snprintf(jobid_str, sizeof(jobid_str), "%" PRIu32, ext_job->job_id);
    next_job->jobid = strdup(jobid_str);

    char en2_hex[65];
    bin2hex(extranonce_2, extranonce_2_len, en2_hex, sizeof(en2_hex));
    next_job->extranonce2 = strdup(en2_hex);

    // strdup Null Kontrolü (İyileştirme 1)
    if (!next_job->jobid || !next_job->extranonce2) {
        ESP_LOGE(TAG, "Failed to allocate memory for SV2 ext job strings");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    next_job->version_mask = version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized, skipping SV2 ext job send");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}
