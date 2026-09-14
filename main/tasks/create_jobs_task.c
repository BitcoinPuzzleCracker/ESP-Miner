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

#define BIP320_FULL_MASK        0x1FFFE000UL
#define MIN_JOB_LIFETIME_MS     12000
#define MAX_JOB_LIFETIME_MS     45000

typedef struct {
    char     job_id[64];
    uint32_t min_version;
    uint32_t max_version;
    int64_t  dispatch_us;
    uint32_t dispatch_count;
} rolling_stats_t;

static rolling_stats_t g_rolling = {0};

typedef struct {
    uint8_t  prev_hash[32];
    uint8_t  merkle0[32];
    uint32_t version;
    uint32_t ntime;
    bool     valid;
} work_fingerprint_t;

static work_fingerprint_t g_last_fp_v1  = {0};
static work_fingerprint_t g_last_fp_sv2 = {0};

static void fp_from_v1(work_fingerprint_t *fp, const mining_notify *n)
{
    memcpy(fp->prev_hash, n->prev_block_hash, 32);
    if (n->n_merkle_branches > 0)
        memcpy(fp->merkle0, n->merkle_branches[0], 32);
    else
        memset(fp->merkle0, 0, 32);
    fp->version = n->version;
    fp->ntime   = n->ntime;
    fp->valid   = true;
}

static void fp_from_sv2(work_fingerprint_t *fp, const sv2_job_t *j)
{
    memcpy(fp->prev_hash, j->prev_hash, 32);
    memcpy(fp->merkle0,   j->merkle_root, 32);
    fp->version = j->version;
    fp->ntime   = j->ntime;
    fp->valid   = true;
}

static void fp_from_sv2_ext(work_fingerprint_t *fp, const sv2_ext_job_t *j)
{
    memcpy(fp->prev_hash, j->prev_hash, 32);
    if (j->merkle_path_count > 0)
        memcpy(fp->merkle0, j->merkle_path[0], 32);
    else
        memset(fp->merkle0, 0, 32);
    fp->version = j->version;
    fp->ntime   = j->ntime;
    fp->valid   = true;
}

static bool fp_equal(const work_fingerprint_t *a, const work_fingerprint_t *b)
{
    if (!a->valid || !b->valid) return false;
    return memcmp(a->prev_hash, b->prev_hash, 32) == 0
        && memcmp(a->merkle0,   b->merkle0,   32) == 0
        && a->version == b->version
        && a->ntime   == b->ntime;
}

static void free_work_item(GlobalState *GLOBAL_STATE, void *work, stratum_protocol_t protocol)
{
    if (!work) return;
    if (protocol == STRATUM_PROTOCOL_V2) {
        if (stratum_v2_is_extended_channel(GLOBAL_STATE))
            sv2_ext_job_free((sv2_ext_job_t *)work);
        else
            free(work);
    } else {
        STRATUM_V1_free_mining_notify(work);
    }
}

static void build_midstates(bm_job *job,
                            uint32_t base_version,
                            const uint8_t *prev_hash,
                            const uint8_t *merkle_root,
                            uint32_t version_mask)
{
    uint8_t midstate_data[64];
    uint8_t midstate[32];

    memcpy(midstate_data,      &base_version, 4);
    memcpy(midstate_data + 4,  prev_hash,     32);
    memcpy(midstate_data + 36, merkle_root,   28);
    midstate_sha256_bin(midstate_data, 64, midstate);
    reverse_32bit_words(midstate, job->midstate);

    if (version_mask == 0) {
        job->num_midstates = 1;
        return;
    }

    uint8_t *ms_ptrs[3] = { job->midstate1, job->midstate2, job->midstate3 };
    uint32_t rolled_version = base_version;
    int produced = 1;

    for (int i = 0; i < 3; i++) {
        rolled_version = increment_bitmask(rolled_version, version_mask);
        if (rolled_version == base_version) break;
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, midstate);
        reverse_32bit_words(midstate, ms_ptrs[i]);
        produced++;
    }

    job->num_midstates = produced;
}

static void update_rolling_stats(const char *job_id, uint32_t version)
{
    if (strcmp(g_rolling.job_id, job_id) != 0) {
        if (g_rolling.job_id[0] != '\0') {
            ESP_LOGI(TAG, "ROLLING STATS [%s]: min=0x%08lx max=0x%08lx span=0x%08lx dispatches=%lu",
                     g_rolling.job_id,
                     (unsigned long)g_rolling.min_version,
                     (unsigned long)g_rolling.max_version,
                     (unsigned long)(g_rolling.max_version - g_rolling.min_version),
                     (unsigned long)g_rolling.dispatch_count);
        }
        strncpy(g_rolling.job_id, job_id, sizeof(g_rolling.job_id) - 1);
        g_rolling.job_id[sizeof(g_rolling.job_id) - 1] = '\0';
        g_rolling.min_version = version;
        g_rolling.max_version = version;
        g_rolling.dispatch_us = esp_timer_get_time();
        g_rolling.dispatch_count = 1;
    } else {
        if (version < g_rolling.min_version) g_rolling.min_version = version;
        if (version > g_rolling.max_version) g_rolling.max_version = version;
        g_rolling.dispatch_count++;
    }
}

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, double difficulty);
static void generate_work_sv2(GlobalState *GLOBAL_STATE, sv2_job_t *job, double difficulty);
static void generate_work_sv2_ext(GlobalState *GLOBAL_STATE, sv2_ext_job_t *job, double difficulty);

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    double difficulty = GLOBAL_STATE->pool_difficulty;
    void *current_work = NULL;
    stratum_protocol_t current_work_protocol = GLOBAL_STATE->stratum_protocol;
    int timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);

    static char     last_dispatched_job_v1[64] = {0};
    static uint32_t last_dispatched_job_sv2    = UINT32_MAX;
    static int64_t  last_dispatch_us           = 0;

    ESP_LOGI(TAG, "ASIC Job Interval: %d ms", timeout_ms);
    ESP_LOGI(TAG, "ASIC Ready! (Zero-Extranonce2 + BIP320 + Auto-Job-Update)");
    ESP_LOGI(TAG, "Version mask: 0x%08lx (BIP320 full=0x%08lx)",
             (unsigned long)GLOBAL_STATE->version_mask,
             (unsigned long)BIP320_FULL_MASK);
    ESP_LOGI(TAG, "Rolling policy: MIN_JOB_LIFETIME=%dms MAX_JOB_LIFETIME=%dms",
             MIN_JOB_LIFETIME_MS, MAX_JOB_LIFETIME_MS);

    while (1) {
        if (GLOBAL_STATE->reset_extranonce2)
            GLOBAL_STATE->reset_extranonce2 = false;

        stratum_protocol_t active_protocol = GLOBAL_STATE->stratum_protocol;
        if (active_protocol != current_work_protocol) {
            if (current_work != NULL) {
                ESP_LOGI(TAG, "Protocol switched, discarding current work");
                free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
                current_work = NULL;
            }
            current_work_protocol = active_protocol;
            last_dispatched_job_v1[0] = '\0';
            last_dispatched_job_sv2    = UINT32_MAX;
            g_last_fp_v1.valid  = false;
            g_last_fp_sv2.valid = false;
        }

        uint64_t start_time = esp_timer_get_time();
        void *new_work = queue_dequeue_timeout(&GLOBAL_STATE->stratum_queue, timeout_ms);
        timeout_ms -= (esp_timer_get_time() - start_time) / 1000;
        if (timeout_ms < 0) timeout_ms = 0;

        if (new_work == NULL) {
            if (current_work == NULL)
                vTaskDelay(100 / portTICK_PERIOD_MS);
            timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
            continue;
        }

        active_protocol = GLOBAL_STATE->stratum_protocol;
        free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
        current_work = NULL;

        if (active_protocol != current_work_protocol) {
            ESP_LOGW(TAG, "Protocol switch during dequeue");
            free(new_work);
            current_work_protocol = active_protocol;
            timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
            continue;
        }

        current_work = new_work;

        bool is_new_job_id  = false;
        bool clean          = false;
        bool work_changed   = false;
        char job_id[64]     = {0};
        uint32_t job_version = 0;

        if (current_work_protocol == STRATUM_PROTOCOL_V2) {
            if (stratum_v2_is_extended_channel(GLOBAL_STATE)) {
                sv2_ext_job_t *j = (sv2_ext_job_t *)current_work;
                snprintf(job_id, sizeof(job_id), "%lu", (unsigned long)j->job_id);
                clean       = j->clean_jobs;
                job_version = j->version;
                ESP_LOGI(TAG, "New Work Dequeued SV2 ext job %s (clean:%d)", job_id, clean);
                if (last_dispatched_job_sv2 != j->job_id) {
                    is_new_job_id = true;
                    last_dispatched_job_sv2 = j->job_id;
                }
                work_fingerprint_t fp;
                fp_from_sv2_ext(&fp, j);
                work_changed = !fp_equal(&g_last_fp_sv2, &fp);
                g_last_fp_sv2 = fp;
            } else {
                sv2_job_t *j = (sv2_job_t *)current_work;
                snprintf(job_id, sizeof(job_id), "%lu", (unsigned long)j->job_id);
                clean       = j->clean_jobs;
                job_version = j->version;
                ESP_LOGI(TAG, "New Work Dequeued SV2 job %s (clean:%d)", job_id, clean);
                if (last_dispatched_job_sv2 != j->job_id) {
                    is_new_job_id = true;
                    last_dispatched_job_sv2 = j->job_id;
                }
                work_fingerprint_t fp;
                fp_from_sv2(&fp, j);
                work_changed = !fp_equal(&g_last_fp_sv2, &fp);
                g_last_fp_sv2 = fp;
            }
        } else {
            mining_notify *j = (mining_notify *)current_work;
            strncpy(job_id, j->job_id, sizeof(job_id) - 1);
            clean       = j->clean_jobs;
            job_version = j->version;
            ESP_LOGI(TAG, "New Work Dequeued %s (clean:%s)", job_id, clean ? "true" : "false");
            if (strcmp(last_dispatched_job_v1, j->job_id) != 0) {
                is_new_job_id = true;
                strncpy(last_dispatched_job_v1, j->job_id, sizeof(last_dispatched_job_v1) - 1);
            }
            work_fingerprint_t fp;
            fp_from_v1(&fp, j);
            work_changed = !fp_equal(&g_last_fp_v1, &fp);
            g_last_fp_v1 = fp;
        }

        if (GLOBAL_STATE->new_set_mining_difficulty_msg) {
            ESP_LOGI(TAG, "New pool difficulty %.2f", GLOBAL_STATE->pool_difficulty);
            difficulty = GLOBAL_STATE->pool_difficulty;
            GLOBAL_STATE->new_set_mining_difficulty_msg = false;
        }

        if (GLOBAL_STATE->new_stratum_version_rolling_msg && GLOBAL_STATE->ASIC_initalized) {
            ESP_LOGI(TAG, "Set chip version rolls 0x%08lx (bits:%d)",
                     (unsigned long)GLOBAL_STATE->version_mask,
                     (int)(GLOBAL_STATE->version_mask >> 13));
            ASIC_set_version_mask(GLOBAL_STATE, GLOBAL_STATE->version_mask);
            GLOBAL_STATE->new_stratum_version_rolling_msg = false;
        }

        int64_t now_us = esp_timer_get_time();
        int64_t since_last_ms = (now_us - last_dispatch_us) / 1000;

        bool should_dispatch;
        if (clean) {
            should_dispatch = true;
        } else if (work_changed && is_new_job_id) {
            if (since_last_ms >= MIN_JOB_LIFETIME_MS) {
                should_dispatch = true;
            } else {
                ESP_LOGI(TAG, "Job %s work changed but only %lld ms old — keeping rolling",
                         job_id, (long long)since_last_ms);
                should_dispatch = false;
            }
        } else if (is_new_job_id && !work_changed) {
            ESP_LOGD(TAG, "Job %s cosmetic change — skipping", job_id);
            should_dispatch = false;
        } else {
            should_dispatch = false;
        }

        if (!should_dispatch && since_last_ms >= MAX_JOB_LIFETIME_MS) {
            ESP_LOGI(TAG, "Job %s max lifetime reached — force dispatch", job_id);
            should_dispatch = true;
        }

        if (!should_dispatch) {
            free_work_item(GLOBAL_STATE, current_work, current_work_protocol);
            current_work = NULL;
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

        update_rolling_stats(job_id, job_version);
        last_dispatch_us = now_us;

        if (active_protocol == STRATUM_PROTOCOL_V2) {
            if (stratum_v2_is_extended_channel(GLOBAL_STATE))
                generate_work_sv2_ext(GLOBAL_STATE, (sv2_ext_job_t *)current_work, difficulty);
            else
                generate_work_sv2(GLOBAL_STATE, (sv2_job_t *)current_work, difficulty);
        } else {
            generate_work(GLOBAL_STATE, (mining_notify *)current_work, difficulty);
        }

        timeout_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    }
}

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, double difficulty)
{
    if (GLOBAL_STATE->extranonce_2_len > MAX_EXTRANONCE2_LEN) {
        ESP_LOGE(TAG, "extranonce_2_len too big");
        return;
    }

    char extranonce_2_str[MAX_EXTRANONCE2_STR];
    memset(extranonce_2_str, '0', GLOBAL_STATE->extranonce_2_len * 2);
    extranonce_2_str[GLOBAL_STATE->extranonce_2_len * 2] = '\0';

    uint8_t coinbase_tx_hash[32];
    calculate_coinbase_tx_hash(notification->coinbase_1, notification->coinbase_2,
                               GLOBAL_STATE->extranonce_str, extranonce_2_str,
                               coinbase_tx_hash);

    uint8_t merkle_root[32];
    calculate_merkle_root_hash(coinbase_tx_hash,
                               (uint8_t (*)[32])notification->merkle_branches,
                               notification->n_merkle_branches, merkle_root);

    bm_job *next_job = malloc(sizeof(bm_job));
    if (!next_job) { ESP_LOGE(TAG, "malloc failed"); return; }
    memset(next_job, 0, sizeof(bm_job));

    next_job->version        = notification->version;
    next_job->target         = notification->target;
    next_job->ntime          = notification->ntime;
    next_job->starting_nonce = 0;
    next_job->pool_diff      = difficulty;

    reverse_32bit_words(merkle_root, next_job->merkle_root);
    reverse_32bit_words(notification->prev_block_hash, next_job->prev_block_hash);

    uint8_t merkle_for_midstate[32];
    memcpy(merkle_for_midstate, merkle_root, 32);
    build_midstates(next_job,
                    notification->version,
                    notification->prev_block_hash,
                    merkle_for_midstate,
                    GLOBAL_STATE->version_mask);

    next_job->extranonce2  = strdup(extranonce_2_str);
    next_job->jobid        = strdup(notification->job_id);
    next_job->version_mask = GLOBAL_STATE->version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ESP_LOGI(TAG, "V1 dispatch %s: midstates=%d mask=0x%08lx",
             notification->job_id, (int)next_job->num_midstates,
             (unsigned long)GLOBAL_STATE->version_mask);

    ASIC_send_work(GLOBAL_STATE, next_job);
}

static void generate_work_sv2(GlobalState *GLOBAL_STATE, sv2_job_t *sv2_job, double difficulty)
{
    bm_job *next_job = malloc(sizeof(bm_job));
    if (!next_job) { ESP_LOGE(TAG, "malloc failed"); return; }
    memset(next_job, 0, sizeof(bm_job));

    uint32_t version_mask = GLOBAL_STATE->version_mask;

    next_job->version        = sv2_job->version;
    next_job->target         = sv2_job->nbits;
    next_job->ntime          = sv2_job->ntime;
    next_job->starting_nonce = 0;
    next_job->pool_diff      = difficulty;

    reverse_32bit_words(sv2_job->merkle_root, next_job->merkle_root);
    reverse_32bit_words(sv2_job->prev_hash, next_job->prev_block_hash);

    build_midstates(next_job, sv2_job->version, sv2_job->prev_hash,
                    sv2_job->merkle_root, version_mask);

    char jobid_str[16];
    snprintf(jobid_str, sizeof(jobid_str), "%" PRIu32, sv2_job->job_id);
    next_job->jobid        = strdup(jobid_str);
    next_job->extranonce2  = strdup("");
    next_job->version_mask = version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ESP_LOGI(TAG, "SV2 dispatch %s: midstates=%d mask=0x%08lx",
             jobid_str, (int)next_job->num_midstates, (unsigned long)version_mask);

    ASIC_send_work(GLOBAL_STATE, next_job);
}

static void generate_work_sv2_ext(GlobalState *GLOBAL_STATE, sv2_ext_job_t *ext_job, double difficulty)
{
    sv2_conn_t *conn = GLOBAL_STATE->sv2_conn;
    if (!conn) return;

    bm_job *next_job = malloc(sizeof(bm_job));
    if (!next_job) { ESP_LOGE(TAG, "malloc failed"); return; }
    memset(next_job, 0, sizeof(bm_job));

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

    next_job->version        = ext_job->version;
    next_job->target         = ext_job->nbits;
    next_job->ntime          = ext_job->ntime;
    next_job->starting_nonce = 0;
    next_job->pool_diff      = difficulty;

    reverse_32bit_words(merkle_root, next_job->merkle_root);
    reverse_32bit_words(ext_job->prev_hash, next_job->prev_block_hash);

    build_midstates(next_job, ext_job->version, ext_job->prev_hash,
                    merkle_root, version_mask);

    char jobid_str[16];
    snprintf(jobid_str, sizeof(jobid_str), "%" PRIu32, ext_job->job_id);
    next_job->jobid = strdup(jobid_str);

    char en2_hex[65];
    bin2hex(extranonce_2, extranonce_2_len, en2_hex, sizeof(en2_hex));
    next_job->extranonce2  = strdup(en2_hex);
    next_job->version_mask = version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ESP_LOGI(TAG, "SV2 ext dispatch %s: midstates=%d mask=0x%08lx",
             jobid_str, (int)next_job->num_midstates, (unsigned long)version_mask);

    ASIC_send_work(GLOBAL_STATE, next_job);
}
