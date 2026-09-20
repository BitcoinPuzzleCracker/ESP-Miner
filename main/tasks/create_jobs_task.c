#include <sys/time.h>
#include <limits.h>

#include "work_queue.h"
#include "global_state.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
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

// Altın Oran (Golden Ratio) copriem adım sabitleri (Maksimum sprekleme / çakışmasız tarama)[span_4](start_span)[span_4](end_span)
#define STEP_GOLDEN_RATIO_64 0x9E3779B97F4A7C15ULL
#define STEP_GOLDEN_RATIO_32 0x9E3779B9ULL

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, uint64_t extranonce_2, double difficulty);
static void generate_work_sv2(GlobalState *GLOBAL_STATE, sv2_job_t *job, double difficulty);
static void generate_work_sv2_ext(GlobalState *GLOBAL_STATE, sv2_ext_job_t *job, double difficulty, uint64_t extranonce_2_counter);

// Havuz extranonce uzunluğuna göre uygun adım boyutunu seç[span_5](start_span)[span_5](end_span)
static inline uint64_t get_extranonce2_step(uint8_t len)
{
    return (len >= 8) ? STEP_GOLDEN_RATIO_64 : STEP_GOLDEN_RATIO_32;
}

// Sayaç değerinin havuz sınırlarını aşmamasını sağla[span_6](start_span)[span_6](end_span)
static inline uint64_t mask_extranonce2(uint64_t val, uint8_t len)
{
    if (len >= 8) {
        return val;
    }
    uint64_t mask = (1ULL << (len * 8)) - 1ULL;
    return val & mask;
}

// Protokole uygun bellek temizleme fonksiyonu[span_7](start_span)[span_7](end_span)[span_8](start_span)[span_8](end_span)
static void free_work_item(GlobalState *GLOBAL_STATE, void *work, stratum_protocol_t protocol)
{
    if (!work) return;
    if (protocol == STRATUM_PROTOCOL_V2) {
        if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
            sv2_ext_job_free((sv2_ext_job_t *)work);
        } else {
            free(work);  // sv2_job_t düz yapıdır
        }
    } else {
        STRATUM_V1_free_mining_notify(work);
    }
}

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    double difficulty = GLOBAL_STATE->pool_difficulty;
    void *current_work = NULL;
    stratum_protocol_t current_work_protocol = GLOBAL_STATE->stratum_protocol;
    
    // Golden Ratio sayaç başlangıcı[span_9](start_span)[span_9](end_span)
    uint64_t extranonce_2 = 0;
    uint64_t extranonce_2_step = get_extranonce2_step(GLOBAL_STATE->extranonce_2_len);

    // İş ID takip hafızaları (Netalsantpool akıllı tetikleme mekanizması)[span_10](start_span)[span_10](end_span)
    static char last_dispatched_job_v1[64] = {0};
    static uint32_t last_dispatched_job_sv2 = UINT32_MAX;

    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms", timeout_ms);
    ESP_LOGI(TAG, "Hibrit Mod Aktif: Akıllı İş Tetikleme + Altın Oran Extranonce Dağıtımı[span_11](start_span)[span_11](end_span)[span_12](start_span)[span_12](end_span)");
    ESP_LOGI(TAG, "Golden Ratio Adım Boyutu: 0x%llx", (unsigned long long)extranonce_2_step);

    while (1) {
        if (GLOBAL_STATE->reset_extranonce2) {
            extranonce_2 = 0;
            extranonce_2_step = get_extranonce2_step(GLOBAL_STATE->extranonce_2_len);
            ESP_LOGI(TAG, "Reset extranonce2 talep edildi. Sayaç sıfırlandı.");
            GLOBAL_STATE->reset_extranonce2 = false;
        }

        // Dinamik protokol kontrolü
        stratum_protocol_t active_protocol = GLOBAL_STATE->stratum_protocol;
        if (active_protocol != current_work_protocol) {
            if (current_work != NULL) {
                ESP_LOGI(TAG, "Protokol değişti (%s -> %s), mevcut iş bırakılıyor",
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
        timeout_ms -= (esp_timer_get_time() - start_time) / 1000;

        if (new_work != NULL) {
            active_protocol = GLOBAL_STATE->stratum_protocol;

            // Önceki işi güvenle temizle[span_13](start_span)[span_13](end_span)[span_14](start_span)[span_14](end_span)
            free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
            current_work = NULL;

            if (active_protocol != current_work_protocol) {
                ESP_LOGW(TAG, "Kuyruktan alma sırasında protokol değişimi algılandı, iş atılıyor");
                free(new_work);
                current_work_protocol = active_protocol;
                timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
                continue;
            }

            current_work = new_work;

            // İş ID takibi ve Netalsantpool akıllı tetikleme bayrakları[span_15](start_span)[span_15](end_span)
            bool is_new_job_id = false;
            bool clean = false;

            if (current_work_protocol == STRATUM_PROTOCOL_V2) {
                if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
                    sv2_ext_job_t *j = (sv2_ext_job_t *)current_work;
                    ESP_LOGI(TAG, "Yeni SV2 Ext İş Alındı ID: %lu", j->job_id);
                    clean = j->clean_jobs;
                    if (last_dispatched_job_sv2 != j->job_id) {
                        is_new_job_id = true;
                        last_dispatched_job_sv2 = j->job_id;
                    }
                } else {
                    sv2_job_t *j = (sv2_job_t *)current_work;
                    ESP_LOGI(TAG, "Yeni SV2 İş Alındı ID: %lu", j->job_id);
                    clean = j->clean_jobs;
                    if (last_dispatched_job_sv2 != j->job_id) {
                        is_new_job_id = true;
                        last_dispatched_job_sv2 = j->job_id;
                    }
                }
            } else {
                mining_notify *j = (mining_notify *)current_work;
                ESP_LOGI(TAG, "Yeni V1 İş Alındı ID: %s (clean: %s)", j->job_id, j->clean_jobs ? "true" : "false");
                clean = j->clean_jobs;
                if (strcmp(last_dispatched_job_v1, j->job_id) != 0) {
                    is_new_job_id = true;
                    strncpy(last_dispatched_job_v1, j->job_id, sizeof(last_dispatched_job_v1) - 1);
                }
            }

            // Zorluk seviyesi güncellemeleri[span_16](start_span)[span_16](end_span)[span_17](start_span)[span_17](end_span)
            if (GLOBAL_STATE->new_set_mining_difficulty_msg) {
                ESP_LOGI(TAG, "Yeni havuz zorluğu: %.2f", GLOBAL_STATE->pool_difficulty);
                difficulty = GLOBAL_STATE->pool_difficulty;
                GLOBAL_STATE->new_set_mining_difficulty_msg = false;
            }

            if (GLOBAL_STATE->new_stratum_version_rolling_msg && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Version maskesi güncelleniyor: %i", (int)(GLOBAL_STATE->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, GLOBAL_STATE->version_mask);
                GLOBAL_STATE->new_stratum_version_rolling_msg = false;
            }

            // NETALSANTPOOL KRİTİK KURALI:
            // İş ID'si yepyeni ise clean_jobs false olsa bile ASIC'e gönder; 
            // aksi takdirde aynı iş tekrarsızsa geç[span_18](start_span)[span_18](end_span).
            if (!is_new_job_id && !clean) {
                continue;
            }

        } else {
            // Kuyruk timeout olduysa
            if (current_work == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }
            timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
            continue;
        }

        // Son protokol tutarlılık kontrolü
        active_protocol = GLOBAL_STATE->stratum_protocol;
        if (active_protocol != current_work_protocol) {
            free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
            current_work = NULL;
            current_work_protocol = active_protocol;
            timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
            continue;
        }

        // ASIC'e işi gönder (Golden Ratio sayaç artışıyla)[span_19](start_span)[span_19](end_span)
        if (active_protocol == STRATUM_PROTOCOL_V2) {
            if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
                generate_work_sv2_ext(GLOBAL_STATE, (sv2_ext_job_t *)current_work, difficulty, extranonce_2);
                extranonce_2 = mask_extranonce2(extranonce_2 + extranonce_2_step, GLOBAL_STATE->extranonce_2_len);
            } else {
                generate_work_sv2(GLOBAL_STATE, (sv2_job_t *)current_work, difficulty);
            }
        } else {
            generate_work(GLOBAL_STATE, (mining_notify *)current_work, extranonce_2, difficulty);
            extranonce_2 = mask_extranonce2(extranonce_2 + extranonce_2_step, GLOBAL_STATE->extranonce_2_len);
        }

        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, uint64_t extranonce_2, double difficulty)
{
    if (GLOBAL_STATE->extranonce_2_len > MAX_EXTRANONCE2_LEN) {
        ESP_LOGE(TAG, "extranonce_2_len sınırı aşıyor");
        return;
    }
    char extranonce_2_str[MAX_EXTRANONCE2_STR];
    extranonce_2_generate(extranonce_2, GLOBAL_STATE->extranonce_2_len, extranonce_2_str);

    uint8_t coinbase_tx_hash[32];
    calculate_coinbase_tx_hash(notification->coinbase_1, notification->coinbase_2, GLOBAL_STATE->extranonce_str, extranonce_2_str, coinbase_tx_hash);

    uint8_t merkle_root[32];
    calculate_merkle_root_hash(coinbase_tx_hash, (uint8_t(*)[32])notification->merkle_branches, notification->n_merkle_branches, merkle_root);

    bm_job *next_job = malloc(sizeof(bm_job));
    if (next_job == NULL) {
        ESP_LOGE(TAG, "Bellek tahsis hatası");
        return;
    }

    construct_bm_job(notification, merkle_root, GLOBAL_STATE->version_mask, difficulty, next_job);

    next_job->extranonce2 = strdup(extranonce_2_str);
    next_job->jobid = strdup(notification->job_id);
    next_job->version_mask = GLOBAL_STATE->version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
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
    if (next_job == NULL) return;

    uint32_t version_mask = GLOBAL_STATE->version_mask;

    next_job->version = sv2_job->version;
    next_job->target = sv2_job->nbits;
    next_job->ntime = sv2_job->ntime;
    next_job->starting_nonce = 0;
    next_job->pool_diff = difficulty;

    reverse_32bit_words(sv2_job->merkle_root, next_job->merkle_root);
    reverse_32bit_words(sv2_job->prev_hash, next_job->prev_block_hash);

    uint8_t midstate_data[64];
    uint32_t base_version = sv2_job->version;
    memcpy(midstate_data, &base_version, 4);
    memcpy(midstate_data + 4, sv2_job->prev_hash, 32);
    memcpy(midstate_data + 36, sv2_job->merkle_root, 28);

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

    char jobid_str[16];
    snprintf(jobid_str, sizeof(jobid_str), "%" PRIu32, sv2_job->job_id);
    next_job->jobid = strdup(jobid_str);
    next_job->extranonce2 = strdup("");
    next_job->version_mask = version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}

static void generate_work_sv2_ext(GlobalState *GLOBAL_STATE, sv2_ext_job_t *ext_job,
                                   double difficulty, uint64_t extranonce_2_counter)
{
    sv2_conn_t *conn = GLOBAL_STATE->sv2_conn;
    if (!conn) return;

    bm_job *next_job = malloc(sizeof(bm_job));
    if (!next_job) return;

    uint32_t version_mask = GLOBAL_STATE->version_mask;

    uint8_t extranonce_2_len = conn->extranonce_size;
    uint8_t extranonce_2[32];
    memset(extranonce_2, 0, sizeof(extranonce_2));
    
    uint64_t temp_counter = extranonce_2_counter;
    for (int i = extranonce_2_len - 1; i >= 0 && temp_counter > 0; i--) {
        extranonce_2[i] = (uint8_t)(temp_counter & 0xFF);
        temp_counter >>= 8;
    }

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

    next_job->version = ext_job->version;
    next_job->target = ext_job->nbits;
    next_job->ntime = ext_job->ntime;
    next_job->starting_nonce = 0;
    next_job->pool_diff = difficulty;

    reverse_32bit_words(merkle_root, next_job->merkle_root);
    reverse_32bit_words(ext_job->prev_hash, next_job->prev_block_hash);

    uint8_t midstate_data[64];
    uint32_t base_version = ext_job->version;
    memcpy(midstate_data, &base_version, 4);
    memcpy(midstate_data + 4, ext_job->prev_hash, 32);
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

    char jobid_str[16];
    snprintf(jobid_str, sizeof(jobid_str), "%" PRIu32, ext_job->job_id);
    next_job->jobid = strdup(jobid_str);

    char en2_hex[65];
    bin2hex(extranonce_2, extranonce_2_len, en2_hex, sizeof(en2_hex));
    next_job->extranonce2 = strdup(en2_hex);
    next_job->version_mask = version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}
