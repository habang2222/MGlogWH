// SPDX-License-Identifier: BSD-2-Clause
// Skeleton lifecycle adapted from libbpf-bootstrap/bootstrap.c.
// Copyright (c) 2020 Facebook. BSD-2-Clause option of its dual license.
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include "event.h"
#include "tenant.h"
#include "quarantine.h"
#include "sensor.skel.h"

_Static_assert(sizeof(struct eq_event) == 232, "event ABI");
_Static_assert(sizeof(struct eq_record) == 240, "record ABI");
#define LANE_COUNT 3
#define RING_COUNT 4
#define META_QUEUE_CAP 4096
#define META_FRAME_MAX (4 * 1024 * 1024)
struct lane {
    FILE *file;
    struct eq_event *queue;
    size_t capacity, head, count;
    uint64_t received, durable, observed, admitted, queue_overflow, high_water;
    int closed, in_flight;
    pthread_cond_t ready;
};
static struct lane lanes[LANE_COUNT]; /* critical, general, quarantine */
static const char *lane_names[] = {"critical", "general", "quarantine"};
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t stopping;
static int failure, dirfd_ = -1, input_done;
static uint64_t max_bytes, general_limit, persist_failed, general_quota_drop;
static uint64_t quarantine_limit, quarantine_storage_drop;
static char run_id[128], manifest_sha256[65], config_sha256[65], boot_id[37];
enum loss_reason { GENERAL_QUOTA, RAW_QUOTA, QUEUE_FULL, Q_STORAGE_LIMIT };
struct meta_item {
    char *payload;
    size_t length;
    struct eq_event event;
    enum loss_reason reason;
    int loss, terminal, lane, control;
    struct eq_quarantine_control transition;
};
static struct {
    FILE *file;
    struct meta_item *queue;
    size_t head, count;
    uint64_t max_bytes, written, seq, committed, committed_seq;
    uint64_t overflow, dropped, persist_failed, high_water;
    uint64_t checkpoint_coalesced;
    size_t checkpoint_pending;
    int closed, in_flight, started;
    pthread_cond_t ready;
} metadata;
struct stream_storage {
    struct eq_quarantine_key key;
    uint64_t appended[3], durable[3]; /* normal critical, Q initial, Q periodic */
    uint64_t queue_rejected[2], storage_rejected[2];
    int used;
};
static struct stream_storage stream_storage[EQ_STREAMS], fallback_storage;
static uint64_t stream_storage_overflow;
static int stream_storage_complete = 1;
static unsigned rule_id(const struct eq_event *event) {
    return (event->quality & EQ_RULE_MASK) >> EQ_RULE_SHIFT;
}
/* The BPF stream map and this table never delete entries during a run. All
 * access is bounded and protected by state_lock; overflow remains explicit. */
static struct stream_storage *storage_for(const struct eq_event *event) {
    if (event->quality & EQ_Q_UNTRACKED) return &fallback_storage;
    struct eq_quarantine_key key = {.cgroup_id = event->cgroup_id, .rule_id = rule_id(event), .kind = event->kind};
    size_t start = (key.cgroup_id ^ (key.cgroup_id >> 32) ^ key.rule_id ^ key.kind) % EQ_STREAMS;
    for (size_t n = 0; n < EQ_STREAMS; n++) {
        struct stream_storage *entry = &stream_storage[(start + n) % EQ_STREAMS];
        if (!entry->used) { entry->used = 1; entry->key = key; return entry; }
        if (!memcmp(&entry->key, &key, sizeof(key))) return entry;
    }
    stream_storage_complete = 0; stream_storage_overflow++;
    return &fallback_storage;
}
static unsigned storage_class(const struct eq_event *event) {
    return !(event->quality & EQ_QUARANTINED) ? 0 : event->quality & EQ_Q_INITIAL ? 1 : 2;
}
static void json_episode(FILE *out, const struct eq_quarantine_episode *episode) {
    fputc('{', out);
#define EP(field) fprintf(out, "\"" #field "\":%llu,", (unsigned long long)episode->field)
    EP(episode_id); EP(start_ns); EP(end_ns); EP(first_sequence); EP(last_sequence);
    EP(last_event_ns); EP(burst_start_ns); EP(peak_rate_eps); EP(high_rate_duration_ms);
    EP(threshold_eps); EP(observed_eps); EP(duration_ms);
    EP(first_pid); EP(first_uid); EP(last_pid); EP(last_uid); EP(seen);
    EP(full_selected); EP(sample_selected); EP(summarized); EP(full_submitted);
    EP(sample_submitted); EP(ring_failed); EP(unique_pid_lower_bound); EP(unique_uid_lower_bound);
    EP(tracking_failed_start); EP(tracking_failed_end);
#undef EP
    fprintf(out, "\"tracking_complete\":%llu}", (unsigned long long)episode->tracking_complete);
}
static void json_storage(FILE *out, const struct stream_storage *storage) {
    fprintf(out, "{\"normal_appended\":%llu,\"normal_durable\":%llu,\"full_appended\":%llu,"
        "\"full_durable\":%llu,\"sample_appended\":%llu,\"sample_durable\":%llu,"
        "\"queue_rejected_full\":%llu,\"queue_rejected_sample\":%llu,"
        "\"storage_rejected_full\":%llu,\"storage_rejected_sample\":%llu}",
        (unsigned long long)storage->appended[0], (unsigned long long)storage->durable[0],
        (unsigned long long)storage->appended[1], (unsigned long long)storage->durable[1],
        (unsigned long long)storage->appended[2], (unsigned long long)storage->durable[2],
        (unsigned long long)storage->queue_rejected[0], (unsigned long long)storage->queue_rejected[1],
        (unsigned long long)storage->storage_rejected[0], (unsigned long long)storage->storage_rejected[1]);
}
static void stop(int sig) { stopping = 1; }
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static int fail(int error, int persistence) {
    pthread_mutex_lock(&state_lock);
    if (!failure) failure = error ? error : EIO;
    if (persistence) persist_failed++;
    int result = -failure;
    pthread_mutex_unlock(&state_lock);
    return result;
}
static int failed(void) {
    pthread_mutex_lock(&state_lock);
    int result = failure;
    pthread_mutex_unlock(&state_lock);
    return result;
}
static const char *loss_name(enum loss_reason reason, int lane) {
    switch (reason) {
    case GENERAL_QUOTA: return "GENERAL_QUOTA";
    case RAW_QUOTA: return "RAW_QUOTA_FAILURE";
    case Q_STORAGE_LIMIT: return "Q_STORAGE_LIMIT";
    default: return lane == 0 ? "CRITICAL_QUEUE_FULL" : lane == 2 ? "Q_QUEUE_FULL" : "GENERAL_QUEUE_FULL";
    }
}
/* Called only with state_lock held. A loss tombstone consumes bounded memory;
 * the ring drain never writes, syncs, or waits for metadata space. */
static void loss_locked(const struct eq_event *event, enum loss_reason reason, int lane) {
    if (!metadata.queue || metadata.closed) return;
    if (metadata.count == META_QUEUE_CAP) {
        metadata.overflow++; metadata.dropped++; return;
    }
    struct meta_item *item = &metadata.queue[(metadata.head + metadata.count) % META_QUEUE_CAP];
    *item = (struct meta_item){.loss = 1, .event = *event, .reason = reason, .lane = lane};
    metadata.count++;
    if (metadata.count > metadata.high_water) metadata.high_water = metadata.count;
    pthread_cond_signal(&metadata.ready);
}
static int save_control(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (size != sizeof(struct eq_quarantine_control)) return fail(EPROTO, 0);
    struct eq_quarantine_control control; memcpy(&control, data, sizeof(control));
    if ((control.transition != EQ_Q_ENTER && control.transition != EQ_Q_EXIT) ||
        (control.reason != EQ_Q_HIGH_RATE && control.reason != EQ_Q_LOW_RATE) ||
        !control.key.rule_id || control.key.rule_id > 255 ||
        (control.key.kind != EQ_OPEN && control.key.kind != EQ_EXEC)) return fail(EPROTO, 0);
    pthread_mutex_lock(&state_lock);
    if (failure || metadata.closed || !metadata.queue) {
        int error = failure ? failure : EPIPE; pthread_mutex_unlock(&state_lock); return -error;
    }
    if (metadata.count == META_QUEUE_CAP) { metadata.overflow++; metadata.dropped++; }
    else {
        struct meta_item *item = &metadata.queue[(metadata.head + metadata.count) % META_QUEUE_CAP];
        *item = (struct meta_item){.control = 1, .transition = control}; metadata.count++;
        if (metadata.count > metadata.high_water) metadata.high_water = metadata.count;
        pthread_cond_signal(&metadata.ready);
    }
    pthread_mutex_unlock(&state_lock); return 0;
}
static int meta_failure(int error) {
    pthread_mutex_lock(&state_lock);
    metadata.persist_failed++;
    if (metadata.queue) pthread_cond_broadcast(&metadata.ready);
    pthread_mutex_unlock(&state_lock);
    return fail(error, 1);
}
static int meta_init(uint64_t limit, int fd) {
    metadata.queue = calloc(META_QUEUE_CAP, sizeof(*metadata.queue));
    if (!metadata.queue) return ENOMEM;
    pthread_condattr_t attributes;
    int error = pthread_condattr_init(&attributes);
    if (!error) {
        error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
        if (!error) error = pthread_cond_init(&metadata.ready, &attributes);
        pthread_condattr_destroy(&attributes);
    }
    if (error) { free(metadata.queue); metadata.queue = NULL; return error; }
    metadata.file = fdopen(fd, "wb");
    if (!metadata.file) {
        error = errno; pthread_cond_destroy(&metadata.ready);
        free(metadata.queue); metadata.queue = NULL; return error;
    }
    metadata.max_bytes = limit;
    setvbuf(metadata.file, NULL, _IOFBF, 64 * 1024);
    return 0;
}
/* fdatasync journal first, then publish its exact committed prefix. A crash
 * reader ignores even valid CRC frames after this fence. */
static int meta_sync(void) {
    if (!metadata.file) return 0;
    if (fflush(metadata.file) || fdatasync(fileno(metadata.file))) return meta_failure(errno);
    FILE *fence = fopen("evidence.meta.commit.tmp", "we");
    if (!fence) return meta_failure(errno);
    fprintf(fence, "{\"schema\":1,\"run_id\":\"%s\",\"manifest_sha256\":\"%s\","
        "\"config_sha256\":\"%s\",\"boot_id\":\"%s\",\"offset\":%llu,\"journal_seq\":%llu}\n",
        run_id, manifest_sha256, config_sha256, boot_id,
        (unsigned long long)metadata.written, (unsigned long long)metadata.seq);
    int bad = ferror(fence) || fflush(fence) || fdatasync(fileno(fence));
    int error = errno;
    if (fclose(fence)) { bad = 1; error = errno; }
    if (bad) return meta_failure(error);
    if (rename("evidence.meta.commit.tmp", "evidence.meta.commit") || fsync(dirfd_))
        return meta_failure(errno);
    pthread_mutex_lock(&state_lock);
    metadata.committed = metadata.written;
    metadata.committed_seq = metadata.seq;
    pthread_mutex_unlock(&state_lock);
    return 0;
}
static int meta_write(const struct meta_item *item) {
    char loss[1024];
    char control_json[4096];
    const char *body = item->payload;
    size_t body_length = item->length;
    if (item->loss) {
        /* Hex keeps the captured bytes exact without putting untrusted path
         * text into JSON. This runs on the metadata writer, not the ring
         * callback; the callback only copies a bounded eq_event. */
        char path_hex[EQ_PATH * 2 + 1];
        static const char hex[] = "0123456789abcdef";
        for (unsigned n = 0; n < item->event.captured_len; n++) {
            unsigned char byte = (unsigned char)item->event.path[n];
            path_hex[2 * n] = hex[byte >> 4];
            path_hex[2 * n + 1] = hex[byte & 15];
        }
        path_hex[2 * item->event.captured_len] = '\0';
        int count = snprintf(loss, sizeof(loss), "{\"record_type\":\"loss\",\"cgroup_id\":%llu,"
            "\"seq\":%llu,\"lane\":\"%s\",\"reason\":\"%s\",\"monotonic_ns\":%llu,"
            "\"witness\":{\"version\":1,\"source\":\"USERSPACE_RING_CALLBACK\","
            "\"event_schema\":%u,\"kind\":%u,\"priority\":%u,\"quality\":%u,"
            "\"rule_id\":%u,\"pid\":%u,\"tid\":%u,\"uid\":%u,"
            "\"process_start_ns\":%llu,\"result\":%lld,\"op_flags\":%u,"
            "\"captured_len\":%u,\"path_hex\":\"%s\"}}",
            (unsigned long long)item->event.cgroup_id, (unsigned long long)item->event.sequence,
            lane_names[item->lane], loss_name(item->reason, item->lane),
            (unsigned long long)item->event.monotonic_ns,
            item->event.schema, item->event.kind, item->event.priority, item->event.quality,
            rule_id(&item->event), item->event.pid, item->event.tid, item->event.uid,
            (unsigned long long)item->event.process_start_ns, (long long)item->event.result,
            item->event.op_flags, item->event.captured_len, path_hex);
        if (count < 0 || (size_t)count >= sizeof(loss)) return meta_failure(EOVERFLOW);
        body = loss; body_length = count;
    } else if (item->control) {
        const struct eq_quarantine_control *control = &item->transition;
        FILE *out = fmemopen(control_json, sizeof(control_json), "w");
        if (!out) return meta_failure(errno);
        fprintf(out, "{\"record_type\":\"quarantine_%s\",\"cgroup_id\":%llu,\"rule_id\":%u,"
            "\"kind\":%u,\"episode_id\":%llu,\"first_seq\":%llu,\"last_seq\":%llu,\"seq\":%llu,"
            "\"monotonic_ns\":%llu,\"threshold_eps\":%llu,\"observed_eps\":%llu,\"duration_ms\":%llu,"
            "\"reason\":\"%s\",\"original_priority\":\"CRITICAL\",\"effective_policy\":\"%s\","
            "\"trigger_reason\":\"%s\",\"episode\":",
            control->transition == EQ_Q_ENTER ? "enter" : "exit", (unsigned long long)control->key.cgroup_id,
            control->key.rule_id, control->key.kind, (unsigned long long)control->episode.episode_id,
            (unsigned long long)control->episode.first_sequence, (unsigned long long)control->episode.last_sequence,
            (unsigned long long)control->transition_sequence, (unsigned long long)control->monotonic_ns,
            (unsigned long long)control->threshold_eps, (unsigned long long)control->observed_eps,
            (unsigned long long)control->duration_ms, control->reason == EQ_Q_HIGH_RATE ? "HIGH_RATE" : "LOW_RATE",
            control->transition == EQ_Q_ENTER ? "QUARANTINE" : "CRITICAL",
            control->transition == EQ_Q_ENTER ? "CRITICAL_RATE_EXCEEDED" : "CRITICAL_RATE_RECOVERED");
        json_episode(out, &control->episode); fputc('}', out);
        long length = ftell(out); int bad = ferror(out); if (fclose(out)) bad = 1;
        if (bad || length < 0 || (size_t)length >= sizeof(control_json)) return meta_failure(EOVERFLOW);
        body = control_json; body_length = length;
    }
    char prefix[512];
    int prefix_length = snprintf(prefix, sizeof(prefix), "{\"schema\":1,\"run_id\":\"%s\","
        "\"manifest_sha256\":\"%s\",\"config_sha256\":\"%s\",\"boot_id\":\"%s\",\"journal_seq\":%llu,",
        run_id, manifest_sha256, config_sha256, boot_id, (unsigned long long)(metadata.seq + 1));
    if (prefix_length < 0 || (size_t)prefix_length >= sizeof(prefix) || !body_length || body[0] != '{')
        return meta_failure(EPROTO);
    size_t length = prefix_length + body_length - 1;
    uint64_t limit = metadata.max_bytes;
    /* Reserve a full maximum frame for a terminal seal. Small 1 MiB budgets
     * may preserve only the seal; dropped reasons remain explicitly degraded. */
    if (!item->terminal) limit = limit > META_FRAME_MAX + 8 ? limit - META_FRAME_MAX - 8 : 0;
    if (length > META_FRAME_MAX || metadata.written + 8 + length > limit) {
        pthread_mutex_lock(&state_lock);
        metadata.dropped++;
        pthread_mutex_unlock(&state_lock);
        if (item->terminal) return meta_failure(EFBIG);
        return 0;
    }
    char *payload = malloc(length);
    if (!payload) return meta_failure(ENOMEM);
    memcpy(payload, prefix, prefix_length); memcpy(payload + prefix_length, body + 1, body_length - 1);
    uint32_t checksum = crc32(0, (void *)payload, length);
    unsigned char header[8];
    for (unsigned n = 0; n < 4; n++) { header[n] = length >> (8 * n); header[n + 4] = checksum >> (8 * n); }
    int bad = fwrite(header, sizeof(header), 1, metadata.file) != 1 ||
        fwrite(payload, length, 1, metadata.file) != 1;
    int error = errno; free(payload);
    if (bad) return meta_failure(error);
    metadata.written += length + 8; metadata.seq++;
    return 0;
}
static void *write_metadata(void *ctx) {
    (void)ctx;
    uint64_t last_sync = now_ms();
    for (;;) {
        pthread_mutex_lock(&state_lock);
        if (!metadata.count && !metadata.closed) {
            struct timespec until; clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec++;
            pthread_cond_timedwait(&metadata.ready, &state_lock, &until);
        }
        int finish = !metadata.count && metadata.closed;
        struct meta_item item = {};
        int have = metadata.count != 0;
        if (have) {
            item = metadata.queue[metadata.head];
            memset(&metadata.queue[metadata.head], 0, sizeof(item));
            metadata.head = (metadata.head + 1) % META_QUEUE_CAP; metadata.count--;
            metadata.in_flight = 1;
            pthread_cond_broadcast(&metadata.ready);
        }
        pthread_mutex_unlock(&state_lock);
        if (finish) break;
        int error = have ? meta_write(&item) : 0;
        free(item.payload);
        pthread_mutex_lock(&state_lock); metadata.in_flight = 0;
        if (have && !item.loss && !item.control && !item.terminal) metadata.checkpoint_pending--;
        pthread_cond_broadcast(&metadata.ready); pthread_mutex_unlock(&state_lock);
        if (error) return NULL;
        uint64_t now = now_ms();
        if (have && item.terminal) { if (meta_sync()) return NULL; last_sync = now; }
        else if (now - last_sync >= 1000) { if (meta_sync()) return NULL; last_sync = now; }
    }
    meta_sync();
    return NULL;
}
/* Snapshot allocations happen on the main thread. The final seal may wait for
 * metadata room after all ring and raw workers have already stopped. */
static int meta_enqueue(char *payload, size_t length, int terminal) {
    pthread_mutex_lock(&state_lock);
    if (!terminal && metadata.checkpoint_pending) {
        metadata.checkpoint_coalesced++;
        pthread_mutex_unlock(&state_lock); free(payload); return 0;
    }
    while (terminal && metadata.count == META_QUEUE_CAP && !metadata.persist_failed)
        pthread_cond_wait(&metadata.ready, &state_lock);
    if (!metadata.queue || metadata.closed || metadata.persist_failed || metadata.count == META_QUEUE_CAP) {
        metadata.overflow++; metadata.dropped++;
        pthread_mutex_unlock(&state_lock); free(payload); return 0;
    }
    struct meta_item *item = &metadata.queue[(metadata.head + metadata.count) % META_QUEUE_CAP];
    *item = (struct meta_item){.payload = payload, .length = length, .terminal = terminal};
    metadata.count++;
    if (!terminal) metadata.checkpoint_pending++;
    if (metadata.count > metadata.high_water) metadata.high_water = metadata.count;
    pthread_cond_signal(&metadata.ready);
    pthread_mutex_unlock(&state_lock);
    return 0;
}
static void meta_close(void) {
    pthread_mutex_lock(&state_lock); metadata.closed = 1;
    if (metadata.queue) pthread_cond_broadcast(&metadata.ready);
    pthread_mutex_unlock(&state_lock);
}
static void meta_wait_idle(void) {
    pthread_mutex_lock(&state_lock);
    while ((metadata.count || metadata.in_flight) && !metadata.persist_failed)
        pthread_cond_wait(&metadata.ready, &state_lock);
    pthread_mutex_unlock(&state_lock);
}
static void meta_destroy(void) {
    if (metadata.file && fclose(metadata.file)) meta_failure(errno);
    metadata.file = NULL;
    if (!metadata.queue) return;
    for (size_t n = 0; n < META_QUEUE_CAP; n++) free(metadata.queue[n].payload);
    free(metadata.queue); metadata.queue = NULL; pthread_cond_destroy(&metadata.ready);
}
static int queue_init(struct lane *lane, size_t capacity) {
    if (!capacity || capacity > SIZE_MAX / sizeof(*lane->queue)) return EINVAL;
    lane->queue = calloc(capacity, sizeof(*lane->queue));
    if (!lane->queue) return ENOMEM;
    pthread_condattr_t attributes;
    int error = pthread_condattr_init(&attributes);
    if (error) { free(lane->queue); lane->queue = NULL; return error; }
    error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    if (!error) error = pthread_cond_init(&lane->ready, &attributes);
    pthread_condattr_destroy(&attributes);
    if (error) { free(lane->queue); lane->queue = NULL; return error; }
    lane->capacity = capacity;
    return 0;
}
static void queues_close(void) {
    pthread_mutex_lock(&state_lock);
    for (int i = 0; i < LANE_COUNT; i++) {
        lanes[i].closed = 1;
        if (lanes[i].queue) pthread_cond_broadcast(&lanes[i].ready);
    }
    pthread_mutex_unlock(&state_lock);
}
static void queue_destroy(struct lane *lane) {
    if (!lane->queue) return;
    pthread_cond_destroy(&lane->ready);
    free(lane->queue);
    lane->queue = NULL;
}
/* The ring callback never performs I/O or waits for space. Reservations include
 * queued and in-flight events so concurrent writers cannot exceed raw quota. */
static int save_event(void *ctx, void *data, size_t size) {
    struct lane *lane = ctx;
    int index = lane - lanes;
    struct eq_event event;
    if (size != sizeof(event)) return fail(EPROTO, 0);
    memcpy(&event, data, size);
    if (event.magic != EQ_MAGIC || event.schema != EQ_SCHEMA ||
        (event.kind != EQ_EXEC && event.kind != EQ_OPEN) || event.priority > EQ_CRITICAL ||
        index < 0 || index >= LANE_COUNT ||
        (event.quality & ~(EQ_CAPTURE_QUALITY_MASK | EQ_QUARANTINED | EQ_Q_INITIAL | EQ_Q_PERIODIC |
            EQ_Q_PROTECTED | EQ_Q_UNTRACKED | EQ_RULE_MASK))) return fail(EPROTO, 0);
    int quarantined = (event.quality & EQ_QUARANTINED) != 0;
    if (!!rule_id(&event) != (event.priority == EQ_CRITICAL) || event.captured_len >= EQ_PATH ||
        (index == 1 && (event.priority == EQ_CRITICAL || quarantined ||
            (event.quality & (EQ_Q_PROTECTED | EQ_Q_UNTRACKED)))) ||
        (index != 1 && event.priority != EQ_CRITICAL) || quarantined != (index == 2) ||
        (quarantined && (!!(event.quality & EQ_Q_INITIAL) == !!(event.quality & EQ_Q_PERIODIC))) ||
        (!quarantined && (event.quality & (EQ_Q_INITIAL | EQ_Q_PERIODIC))) ||
        (quarantined && (event.quality & EQ_Q_PROTECTED)) ||
        ((event.quality & EQ_Q_UNTRACKED) && !quarantined && !(event.quality & EQ_Q_PROTECTED))) return fail(EPROTO, 0);
    pthread_mutex_lock(&state_lock);
    if (failure || lane->closed) {
        int error = failure ? failure : EPIPE;
        pthread_mutex_unlock(&state_lock);
        return -error;
    }
    lane->observed++;
    struct stream_storage *storage = index == 1 ? NULL : storage_for(&event);
    unsigned class = storage_class(&event), sample_class = class == 1 ? 0 : 1;
    uint64_t noncritical = (lanes[1].admitted + lanes[2].admitted + 1) * sizeof(struct eq_record);
    uint64_t total = (lanes[0].admitted + lanes[1].admitted + lanes[2].admitted + 1) * sizeof(struct eq_record);
    if (index == 2 && ((lane->admitted + 1) * sizeof(struct eq_record) > quarantine_limit ||
        noncritical > general_limit || total > max_bytes)) {
        quarantine_storage_drop++; storage->storage_rejected[sample_class]++;
        loss_locked(&event, Q_STORAGE_LIMIT, index);
        pthread_mutex_unlock(&state_lock); return 0;
    }
    if (index == 1 && noncritical > general_limit) {
        general_quota_drop++;
        loss_locked(&event, GENERAL_QUOTA, index);
        pthread_mutex_unlock(&state_lock);
        return 0; /* Explicit quota loss; continue servicing the critical reserve. */
    }
    if (total > max_bytes) {
        persist_failed++; failure = EFBIG;
        loss_locked(&event, RAW_QUOTA, index);
        pthread_mutex_unlock(&state_lock);
        return -EFBIG;
    }
    if (lane->count >= lane->capacity) {
        lane->queue_overflow++;
        if (index == 2) storage->queue_rejected[sample_class]++;
        loss_locked(&event, QUEUE_FULL, index);
        pthread_mutex_unlock(&state_lock);
        return 0;
    }
    lane->queue[(lane->head + lane->count) % lane->capacity] = event;
    lane->count++;
    lane->admitted++;
    if (lane->count > lane->high_water) lane->high_water = lane->count;
    pthread_cond_signal(&lane->ready);
    pthread_mutex_unlock(&state_lock);
    return 0;
}
/* Only the owning writer accesses its FILE. Counter snapshots take the mutex,
 * while slow writes and syncs hold no collector/queue lock. */
static int sync_lane(struct lane *lane) {
    if (!lane->file) return 0;
    if (fflush(lane->file) || fdatasync(fileno(lane->file))) return fail(errno, 1);
    pthread_mutex_lock(&state_lock);
    lane->durable = lane->received * sizeof(struct eq_record);
    int index = lane - lanes;
    for (size_t n = 0; n <= EQ_STREAMS; n++) {
        struct stream_storage *storage = n == EQ_STREAMS ? &fallback_storage : &stream_storage[n];
        if (index == 0) storage->durable[0] = storage->appended[0];
        else if (index == 2) {
            storage->durable[1] = storage->appended[1]; storage->durable[2] = storage->appended[2];
        }
    }
    pthread_mutex_unlock(&state_lock);
    return 0;
}
static void *write_lane(void *ctx) {
    struct lane *lane = ctx;
    uint64_t last_sync = now_ms();
    for (;;) {
        struct eq_record record = {};
        pthread_mutex_lock(&state_lock);
        if (!lane->count && !lane->closed) {
            struct timespec until;
            clock_gettime(CLOCK_MONOTONIC, &until);
            until.tv_sec++;
            pthread_cond_timedwait(&lane->ready, &state_lock, &until);
        }
        int finish = !lane->count && lane->closed;
        int have_event = lane->count != 0;
        if (have_event) {
            record.event = lane->queue[lane->head];
            lane->head = (lane->head + 1) % lane->capacity;
            lane->count--;
            lane->in_flight = 1;
        }
        pthread_mutex_unlock(&state_lock);
        if (finish) break;
        if (have_event) {
            record.crc32 = crc32(0, (void *)&record.event, sizeof(record.event));
            int error = fwrite(&record, sizeof(record), 1, lane->file) != 1;
            int saved_errno = errno;
            pthread_mutex_lock(&state_lock);
            lane->in_flight = 0;
            if (!error) {
                lane->received++;
                if (lane != &lanes[1]) storage_for(&record.event)->appended[storage_class(&record.event)]++;
            }
            pthread_mutex_unlock(&state_lock);
            if (error) { fail(saved_errno, 1); return NULL; }
        }
        uint64_t now = now_ms();
        if (now - last_sync >= 1000) {
            if (sync_lane(lane)) return NULL;
            last_sync = now;
        }
    }
    sync_lane(lane);
    return NULL;
}
struct drain_context { struct ring_buffer *rings[RING_COUNT]; };
static void *drain_rings(void *ctx) {
    struct drain_context *drain = ctx;
    while (!failed()) {
        int critical = ring_buffer__consume_n(drain->rings[0], 256);
        int general = failed() ? 0 : ring_buffer__consume_n(drain->rings[1], 1024);
        int quarantine = failed() ? 0 : ring_buffer__consume_n(drain->rings[2], 128);
        int control = failed() ? 0 : ring_buffer__consume_n(drain->rings[3], 64);
        if (critical < 0 || general < 0 || quarantine < 0 || control < 0) { fail(EIO, 0); break; }
        pthread_mutex_lock(&state_lock);
        int finish = input_done;
        pthread_mutex_unlock(&state_lock);
        if (finish && !critical && !general && !quarantine && !control) break;
        if (!critical && !general && !quarantine && !control) usleep(1000);
    }
    return NULL;
}
static int publish_snapshot(char *payload, size_t length, int journal, int terminal) {
    /* Terminal health is published only by the final caller, after the metadata
     * worker has committed its seal and joined. Queueing a seal is not STOPPED. */
    if (journal && terminal) return meta_enqueue(payload, length, 1);
    FILE *out = fopen("health.json.tmp", "we");
    if (!out) { free(payload); return -1; }
    int bad = fwrite(payload, length, 1, out) != 1 || fflush(out) || fdatasync(fileno(out));
    if (fclose(out)) bad = 1;
    if (bad || rename("health.json.tmp", "health.json") || fsync(dirfd_)) { free(payload); return -1; }
    if (journal) meta_enqueue(payload, length, 0);
    else free(payload);
    return 0;
}
static void json_engine(FILE *out, const struct eq_quarantine_engine *engine) {
    fputc('{', out);
#define EN(field) fprintf(out, "\"" #field "\":%llu,", (unsigned long long)engine->field)
    EN(initialized); EN(window_start_ns); EN(window_count); EN(window_complete);
    EN(accounted_seen); EN(high_windows); EN(low_windows); EN(quarantined); EN(next_sample_ns);
    EN(current_rate_eps); EN(peak_rate_eps); EN(burst_start_ns);
    EN(q_seen); EN(full_selected); EN(sample_selected); EN(summarized);
    EN(full_submitted); EN(sample_submitted); EN(ring_failed); EN(enter_count); EN(exit_count);
#undef EN
    fputs("\"current\":", out); json_episode(out, &engine->current);
    fputs(",\"last\":", out); json_episode(out, &engine->last); fputc('}', out);
}
static const struct stream_storage *storage_snapshot_for(const struct stream_storage *entries,
                                                         const struct eq_quarantine_key *key) {
    size_t start = (key->cgroup_id ^ (key->cgroup_id >> 32) ^ key->rule_id ^ key->kind) % EQ_STREAMS;
    for (size_t n = 0; n < EQ_STREAMS; n++) {
        const struct stream_storage *entry = &entries[(start + n) % EQ_STREAMS];
        if (!entry->used) break;
        if (!memcmp(&entry->key, key, sizeof(*key))) return entry;
    }
    static const struct stream_storage empty;
    return &empty;
}
static int snapshot(struct sensor_bpf *skel, const char *state, int journal) {
    struct {
        uint64_t appended, durable, observed, admitted, overflow, high_water, queued, in_flight, capacity;
    } view[LANE_COUNT];
    struct stream_storage *storage_view = calloc(EQ_STREAMS, sizeof(*storage_view));
    if (!storage_view) { errno = ENOMEM; return -1; }
    pthread_mutex_lock(&state_lock);
    for (int i = 0; i < LANE_COUNT; i++) {
        view[i].appended = lanes[i].received; view[i].durable = lanes[i].durable;
        view[i].observed = lanes[i].observed; view[i].admitted = lanes[i].admitted;
        view[i].overflow = lanes[i].queue_overflow; view[i].high_water = lanes[i].high_water;
        view[i].queued = lanes[i].count; view[i].in_flight = lanes[i].in_flight; view[i].capacity = lanes[i].capacity;
    }
    memcpy(storage_view, stream_storage, EQ_STREAMS * sizeof(*storage_view));
    struct stream_storage fallback_view = fallback_storage;
    uint64_t storage_overflow = stream_storage_overflow; int storage_complete = stream_storage_complete;
    int snapshot_failure = failure;
    uint64_t snapshot_persist_failed = persist_failed, quota_drop = general_quota_drop, q_quota_drop = quarantine_storage_drop;
    uint64_t meta_committed = metadata.committed, meta_seq = metadata.committed_seq;
    uint64_t meta_overflow = metadata.overflow, meta_dropped = metadata.dropped;
    uint64_t meta_failed = metadata.persist_failed, meta_depth = metadata.count, meta_high = metadata.high_water;
    uint64_t meta_coalesced = metadata.checkpoint_coalesced; int meta_closed = metadata.closed;
    pthread_mutex_unlock(&state_lock);
    char *payload = NULL; size_t payload_length = 0;
    FILE *out = open_memstream(&payload, &payload_length);
    if (!out) { free(storage_view); return -1; }
    struct rusage usage = {}; getrusage(RUSAGE_SELF, &usage);
    fprintf(out, "{\"record_type\":\"%s\",\"version\":\"0.3.0\",\"raw_schema\":2,\"state\":\"%s\",\"pid\":%d,"
        "\"monotonic_ms\":%llu,\"error_errno\":%d,\"persist_failed\":%llu,\"record_size\":240,"
        "\"general_quota_drop\":%llu,\"quarantine_storage_drop\":%llu,\"writer_threads\":3,"
        "\"dedicated_drain_thread\":true,\"critical_scheduler\":\"FIFO\","
        "\"cpu_seconds\":%.6f,\"max_rss_kib\":%ld,\"summary_kind\":\"AGGREGATE_ONLY\",",
        !strcmp(state, "RUNNING") ? "checkpoint" : "seal", state, getpid(), (unsigned long long)now_ms(),
        snapshot_failure, (unsigned long long)snapshot_persist_failed, (unsigned long long)quota_drop,
        (unsigned long long)q_quota_drop, usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 +
        usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6, usage.ru_maxrss);
    fputs("\"durable\":{", out);
    for (int i = 0; i < LANE_COUNT; i++) fprintf(out, "%s\"%s.raw\":%llu", i ? "," : "", lane_names[i], (unsigned long long)view[i].durable);
    fputs("},\"durable_offsets\":{", out);
    for (int i = 0; i < LANE_COUNT; i++) fprintf(out, "%s\"%s\":%llu", i ? "," : "", lane_names[i], (unsigned long long)view[i].durable);
    fputc('}', out);
#define LANE_ARRAY(label, field) do { fputs(",\"" label "\":[", out); \
    for (int i = 0; i < LANE_COUNT; i++) { fprintf(out, "%s%llu", i ? "," : "", (unsigned long long)view[i].field); } \
    fputc(']', out); } while (0)
    LANE_ARRAY("appended", appended); LANE_ARRAY("received", observed); LANE_ARRAY("admitted", admitted);
    LANE_ARRAY("queue_capacity", capacity); LANE_ARRAY("queue_depth", queued); LANE_ARRAY("queue_in_flight", in_flight);
    LANE_ARRAY("queue_high_water", high_water); LANE_ARRAY("queue_overflow", overflow);
#undef LANE_ARRAY
    fprintf(out, ",\"metadata\":{\"committed_offset\":%llu,\"committed_seq\":%llu,\"overflow\":%llu,"
        "\"dropped\":%llu,\"persist_failed\":%llu,\"queue_capacity\":4096,\"queue_depth\":%llu,"
        "\"queue_high_water\":%llu,\"checkpoint_coalesced\":%llu,\"state\":\"%s\"},"
        "\"metadata_overflow\":%llu,\"metadata_dropped\":%llu,\"metadata_failed\":%s,\"exact_loss_available\":%s,"
        "\"exact_loss_scope\":\"USERSPACE_REJECTIONS\",\"tenants\":[",
        (unsigned long long)meta_committed, (unsigned long long)meta_seq, (unsigned long long)meta_overflow,
        (unsigned long long)meta_dropped, (unsigned long long)meta_failed, (unsigned long long)meta_depth,
        (unsigned long long)meta_high, (unsigned long long)meta_coalesced,
        meta_failed ? "FAILED" : meta_dropped || meta_overflow ? "DEGRADED" : meta_closed ? "STOPPED" : "RUNNING",
        (unsigned long long)meta_overflow, (unsigned long long)meta_dropped, meta_failed ? "true" : "false",
        metadata.started && !meta_failed && !meta_dropped && !meta_overflow ? "true" : "false");
    int first = 1, fd = bpf_map__fd(skel->maps.tenants), sequence_complete = 1;
    uint64_t key = 0, next; void *previous = NULL; int n;
    for (n = 0; n < EQ_TENANTS; n++) {
        if (bpf_map_get_next_key(fd, previous, &next)) { if (errno != ENOENT) sequence_complete = 0; break; }
        struct eq_tenant_stats tenant;
        if (!bpf_map_lookup_elem(fd, &next, &tenant)) {
            fprintf(out, "%s{\"cgroup_id\":%llu,\"sequence\":%llu,\"submitted\":[%llu,%llu,%llu],",
                first ? "" : ",", (unsigned long long)next, (unsigned long long)tenant.sequence,
                (unsigned long long)tenant.submitted[0], (unsigned long long)tenant.submitted[1], (unsigned long long)tenant.submitted[2]);
#define TN(field) fprintf(out, "\"" #field "\":%llu,", (unsigned long long)tenant.field)
            TN(budget_suppress); TN(general_full); TN(critical_full); TN(budget_contention);
            TN(quarantine_submitted); TN(quarantine_full); TN(quarantine_summarized); TN(stream_map_full);
#undef TN
            fprintf(out, "\"stream_contention\":%llu}", (unsigned long long)tenant.stream_contention); first = 0;
        } else sequence_complete = 0;
        key = next; previous = &key;
    }
    if (n == EQ_TENANTS && (!bpf_map_get_next_key(fd, previous, &next) || errno != ENOENT)) sequence_complete = 0;
    fputs("],\"streams\":[", out);
    struct eq_quarantine_key stream_key = {}, stream_next; previous = NULL;
    int streams_complete = 1, tracking_complete = 1; first = 1; fd = bpf_map__fd(skel->maps.quarantine_streams);
    uint64_t critical_seen = 0, q_seen = 0, summarized = 0, full_selected = 0, sample_selected = 0;
    uint64_t full_submitted = 0, sample_submitted = 0, ring_failed = 0, enters = 0, exits = 0, current_streams = 0;
    uint64_t peak_rate = 0;
    for (n = 0; n < EQ_STREAMS; n++) {
        if (bpf_map_get_next_key(fd, previous, &stream_next)) { if (errno != ENOENT) streams_complete = 0; break; }
        struct eq_quarantine_stream stream;
        if (!bpf_map_lookup_elem(fd, &stream_next, &stream)) {
            fprintf(out, "%s{\"cgroup_id\":%llu,\"rule_id\":%u,\"kind\":%u,", first ? "" : ",",
                (unsigned long long)stream_next.cgroup_id, stream_next.rule_id, stream_next.kind);
#define ST(field) fprintf(out, "\"" #field "\":%llu,", (unsigned long long)stream.field)
            ST(seen); ST(tracking_failed); ST(protected_seen); ST(critical_submitted); ST(critical_ring_failed);
            ST(untracked_seen); ST(untracked_selected); ST(untracked_summarized); ST(untracked_submitted);
            ST(untracked_ring_failed); ST(transition_ring_failed);
#undef ST
            if (stream.tracking_failed) {
                tracking_complete = 0;
                stream.engine.current.tracking_complete = 0; stream.engine.last.tracking_complete = 0;
            }
            fputs("\"engine\":", out); json_engine(out, &stream.engine);
            fputs(",\"collector\":", out); json_storage(out, storage_snapshot_for(storage_view, &stream_next));
            fputc('}', out); first = 0;
            critical_seen += stream.seen; q_seen += stream.engine.q_seen; summarized += stream.engine.summarized;
            full_selected += stream.engine.full_selected; sample_selected += stream.engine.sample_selected;
            full_submitted += stream.engine.full_submitted; sample_submitted += stream.engine.sample_submitted;
            ring_failed += stream.engine.ring_failed; enters += stream.engine.enter_count; exits += stream.engine.exit_count;
            current_streams += !!stream.engine.quarantined;
            if (stream.engine.peak_rate_eps > peak_rate) peak_rate = stream.engine.peak_rate_eps;
        } else streams_complete = 0;
        stream_key = stream_next; previous = &stream_key;
    }
    if (n == EQ_STREAMS && (!bpf_map_get_next_key(fd, previous, &stream_next) || errno != ENOENT)) streams_complete = 0;
    struct eq_quarantine_global global = {}; unsigned global_key = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.quarantine_global), &global_key, &global)) streams_complete = 0;
    critical_seen = global.critical_events_total; q_seen = global.quarantined_events_total;
    if (global.stream_map_full || global.state_contention) tracking_complete = 0;
    summarized += global.untracked_summarized; sample_selected += global.untracked_selected;
    sample_submitted += global.untracked_submitted; ring_failed += global.untracked_ring_failed;
    fputs("],\"quarantine_global\":{", out);
#define GL(field) fprintf(out, "\"" #field "\":%llu,", (unsigned long long)global.field)
    GL(critical_events_total); GL(protected_events_total); GL(quarantined_events_total);
    GL(stream_map_full); GL(state_contention); GL(untracked_seen); GL(untracked_selected); GL(untracked_summarized);
    GL(untracked_submitted); GL(untracked_ring_failed); GL(untracked_protected); GL(untracked_protected_submitted);
    GL(untracked_protected_ring_failed);
#undef GL
    fprintf(out, "\"transition_ring_failed\":%llu},\"untracked_collector\":", (unsigned long long)global.transition_ring_failed);
    json_storage(out, &fallback_view);
    uint64_t full_saved = fallback_view.durable[1], sample_saved = fallback_view.durable[2];
    uint64_t full_appended = fallback_view.appended[1], sample_appended = fallback_view.appended[2];
    for (n = 0; n < EQ_STREAMS; n++) {
        full_saved += storage_view[n].durable[1]; sample_saved += storage_view[n].durable[2];
        full_appended += storage_view[n].appended[1]; sample_appended += storage_view[n].appended[2];
    }
    int accounting_final = !strcmp(state, "STOPPED") && streams_complete && storage_complete && tracking_complete;
    uint64_t not_durable = q_seen >= full_saved + sample_saved ? q_seen - full_saved - sample_saved : 0;
    fprintf(out, ",\"active_quarantined_streams\":%llu,\"critical_events_total\":%llu,"
        "\"quarantined_events_total\":%llu,\"peak_critical_rate\":%llu,"
        "\"peak_critical_rate_scope\":\"MAX_TRACKED_STREAM_ONE_SECOND_EPS\","
        "\"quarantine_by_reason\":{\"CRITICAL_RATE_EXCEEDED\":%llu,\"CRITICAL_RATE_RECOVERED\":%llu},"
        "\"quarantine_by_reason_scope\":\"TRANSITIONS\"",
        (unsigned long long)current_streams, (unsigned long long)critical_seen, (unsigned long long)q_seen,
        (unsigned long long)peak_rate, (unsigned long long)enters, (unsigned long long)exits);
    fprintf(out, ",\"stream_snapshot_complete\":%s,\"stream_storage_complete\":%s,\"stream_storage_overflow\":%llu,"
        "\"quarantine_tracking_complete\":%s,\"critical_seen_total\":%llu,\"protected_critical_seen_total\":%llu,"
        "\"quarantine_seen_total\":%llu,\"quarantine_full_selected_total\":%llu,"
        "\"quarantine_sample_selected_total\":%llu,\"quarantine_summarized_total\":%llu,"
        "\"quarantine_full_submitted_total\":%llu,\"quarantine_sample_submitted_total\":%llu,\"quarantine_ring_failed_total\":%llu,"
        "\"quarantine_full_appended_total\":%llu,\"quarantine_sample_appended_total\":%llu,"
        "\"quarantine_full_saved_total\":%llu,\"quarantine_sampled_total\":%llu,\"quarantine_enter_total\":%llu,"
        "\"quarantine_exit_total\":%llu,\"quarantined_streams\":%llu,\"quarantine_accounting_final\":%s,"
        "\"quarantine_not_stored_observed_total\":%llu,\"quarantine_pending_total\":%llu,\"quarantine_dropped_total\":",
        streams_complete ? "true" : "false", storage_complete ? "true" : "false", (unsigned long long)storage_overflow,
        tracking_complete ? "true" : "false", (unsigned long long)critical_seen,
        (unsigned long long)global.protected_events_total, (unsigned long long)q_seen, (unsigned long long)full_selected,
        (unsigned long long)sample_selected, (unsigned long long)summarized, (unsigned long long)full_submitted,
        (unsigned long long)sample_submitted, (unsigned long long)ring_failed, (unsigned long long)full_appended,
        (unsigned long long)sample_appended, (unsigned long long)full_saved, (unsigned long long)sample_saved,
        (unsigned long long)enters, (unsigned long long)exits, (unsigned long long)current_streams,
        accounting_final ? "true" : "false", (unsigned long long)not_durable,
        (unsigned long long)(view[2].admitted >= full_saved + sample_saved ? view[2].admitted - full_saved - sample_saved : 0));
    if (accounting_final) fprintf(out, "%llu", (unsigned long long)not_durable); else fputs("null", out);
    fputs(",\"faults\":[", out);
    int cpus = libbpf_num_possible_cpus(); uint64_t *values = cpus > 0 ? calloc(cpus, sizeof(*values)) : NULL;
    if (!values) { fclose(out); free(payload); free(storage_view); errno = ENOMEM; return -1; }
    for (unsigned i = 0; i < 4; i++) {
        uint64_t sum = 0;
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.faults), &i, values)) {
            free(values); fclose(out); free(payload); free(storage_view); return -1;
        }
        for (int c = 0; c < cpus; c++) sum += values[c];
        fprintf(out, "%s%llu", i ? "," : "", (unsigned long long)sum);
    }
    free(values); free(storage_view);
    fprintf(out, "],\"sequence_snapshot_complete\":%s,\"fault_snapshot_complete\":true}\n", sequence_complete ? "true" : "false");
    int bad = ferror(out); if (fclose(out)) bad = 1;
    if (bad) { free(payload); return -1; }
    return publish_snapshot(payload, payload_length, journal, strcmp(state, "RUNNING") != 0);
}
static int parse_number(const char *text, uint64_t low, uint64_t high, uint64_t *value) {
    if (!text || !*text || text[0] == '-' || text[0] == '+') return -1;
    char *end; errno = 0; unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || *end || parsed < low || parsed > high) return -1;
    *value = parsed; return 0;
}
static int copy_identity(char *dest, size_t capacity, const char *name, int uuid) {
    const char *value = getenv(name);
    size_t wanted = uuid ? 36 : 64;
    if (!value || strlen(value) != wanted || capacity <= wanted) return -1;
    for (size_t n = 0; n < wanted; n++) {
        if (uuid && (n == 8 || n == 13 || n == 18 || n == 23)) {
            if (value[n] != '-') return -1;
        } else if (!((value[n] >= '0' && value[n] <= '9') || (value[n] >= 'a' && value[n] <= 'f'))) return -1;
    }
    memcpy(dest, value, wanted + 1); return 0;
}
int main(int argc, char **argv) {
    pid_t parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent) return 1;
    if (argc != 7 && argc < 20) {
        fprintf(stderr, "usage: collector DIR RATE BURST PATH MAX_MIB RESERVE_MIB [META_MIB Q_MIB THRESHOLD DURATION_MS RECOVERY_THRESHOLD COOLDOWN_MS INITIAL_FULL SAMPLE_INTERVAL_MS RULE_COUNT ID KIND PROTECTED PATH ...]\n"); return 2;
    }
    uint64_t rate, burst, max_mib, reserve, meta_mib = 16, q_mib = 16, count = 1;
    struct eq_quarantine_config q_config = {.threshold_eps = 10000, .duration_ms = 3000,
        .recovery_eps = 2000, .cooldown_ms = 10000, .initial_full = 8, .sample_interval_ms = 100};
    struct eq_quarantine_rule rules[EQ_RULES] = {{.id = 1, .kind = EQ_OPEN, .enabled = 1}};
    if (parse_number(argv[2], 1, 1000000, &rate) || parse_number(argv[3], 1, 1000000, &burst) ||
        parse_number(argv[5], 16, 1024, &max_mib) || parse_number(argv[6], 0, 1023, &reserve) ||
        reserve >= max_mib || strlen(argv[4]) > EQ_PATH - 2 || argv[4][0] != '/') return 2;
    strcpy(rules[0].path, argv[4]);
    if (argc != 7) {
        uint64_t threshold, duration, recovery, cooldown, initial, interval;
        if (parse_number(argv[7], 8, 64, &meta_mib) || parse_number(argv[8], 1, 256, &q_mib) ||
            parse_number(argv[9], 1, 1000000, &threshold) || parse_number(argv[10], 1000, 60000, &duration) ||
            parse_number(argv[11], 0, 999999, &recovery) || parse_number(argv[12], 1000, 600000, &cooldown) ||
            parse_number(argv[13], 0, 64, &initial) || parse_number(argv[14], 10, 60000, &interval) ||
            parse_number(argv[15], 1, EQ_RULES, &count) || argc != 16 + 4 * (int)count || recovery >= threshold) return 2;
        q_config = (struct eq_quarantine_config){.threshold_eps = threshold, .duration_ms = duration,
            .recovery_eps = recovery, .cooldown_ms = cooldown, .initial_full = initial, .sample_interval_ms = interval};
        memset(rules, 0, sizeof(rules));
        for (unsigned n = 0; n < count; n++) {
            int base = 16 + 4 * n; uint64_t id, kind, protected_rule;
            if (parse_number(argv[base], 1, 255, &id) || parse_number(argv[base + 1], EQ_EXEC, EQ_OPEN, &kind) ||
                parse_number(argv[base + 2], 0, 1, &protected_rule) || argv[base + 3][0] != '/' ||
                strlen(argv[base + 3]) > EQ_PATH - 2) return 2;
            for (unsigned previous = 0; previous < n; previous++) if (rules[previous].id == id) return 2;
            rules[n] = (struct eq_quarantine_rule){.id = id, .kind = kind, .protected_rule = protected_rule, .enabled = 1};
            strcpy(rules[n].path, argv[base + 3]);
        }
    } else if (q_mib > max_mib - reserve) q_mib = max_mib - reserve;
    if (q_mib > max_mib - reserve) return 2;
    if (copy_identity(run_id, sizeof(run_id), "MGLOGWH_RUN_ID", 1) ||
        copy_identity(manifest_sha256, sizeof(manifest_sha256), "MGLOGWH_MANIFEST_SHA256", 0) ||
        copy_identity(config_sha256, sizeof(config_sha256), "MGLOGWH_CONFIG_SHA256", 0) ||
        copy_identity(boot_id, sizeof(boot_id), "MGLOGWH_BOOT_ID", 1)) {
        fprintf(stderr, "collector requires validated run lineage from manage.py\n"); return 2;
    }
    max_bytes = (uint64_t)max_mib * 1024 * 1024;
    general_limit = (uint64_t)(max_mib - reserve) * 1024 * 1024;
    quarantine_limit = q_mib * 1024 * 1024;
    umask(0077);
    if (chdir(argv[1]) || (dirfd_ = open(".", O_RDONLY | O_DIRECTORY)) < 0) { perror("run directory"); return 1; }
    char directory[PATH_MAX];
    if (!getcwd(directory, sizeof(directory)) || strcmp(strrchr(directory, '/') + 1, run_id)) {
        fprintf(stderr, "run directory does not match run lineage\n"); close(dirfd_); return 2;
    }
    signal(SIGINT, stop); signal(SIGTERM, stop);
    struct sensor_bpf *skel = sensor_bpf__open();
    struct ring_buffer *rings[RING_COUNT] = {};
    pthread_t writers[LANE_COUNT], drain_thread, metadata_thread;
    int writers_started[LANE_COUNT] = {}, drain_started = 0;
    struct drain_context drain = {};
    int loaded = 0;
    if (!skel) { failure = EINVAL; goto done; }
    skel->rodata->bulk_rate = rate; skel->rodata->bulk_burst = burst;
    skel->rodata->quarantine_config = q_config; skel->rodata->rule_count = count;
    memcpy((void *)skel->rodata->critical_rules, rules, sizeof(rules));
    skel->rodata->self_pid = getpid();
    struct stat ns;
    if (stat("/proc/self/ns/pid", &ns)) { failure = errno; goto done; }
    skel->rodata->self_ns_dev = ns.st_dev; skel->rodata->self_ns_ino = ns.st_ino;
    if (sensor_bpf__load(skel)) { failure = EINVAL; goto done; }
    loaded = 1;
    const char *names[] = {"critical.raw", "general.raw", "quarantine.raw"};
    for (int i = 0; i < LANE_COUNT; i++) {
        int file = open(names[i], O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (file < 0) { failure = errno; goto done; }
        lanes[i].file = fdopen(file, "wb");
        if (!lanes[i].file) { close(file); failure = errno; goto done; }
        setvbuf(lanes[i].file, NULL, _IOFBF, 256 * 1024);
        int error = queue_init(&lanes[i], i == 0 ? 8192 : i == 1 ? 16384 : 512);
        if (error) { failure = error; goto done; }
    }
    int meta_fd = open("evidence.meta", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (meta_fd < 0) { failure = errno; goto done; }
    int error = meta_init(meta_mib * 1024 * 1024, meta_fd);
    if (error) { close(meta_fd); failure = error; goto done; }
    if (fsync(dirfd_)) { failure = errno; goto done; }
    if (meta_sync()) goto done;
    error = pthread_create(&metadata_thread, NULL, write_metadata, NULL);
    if (error) { fail(error, 0); goto done; }
    metadata.started = 1;
    rings[0] = ring_buffer__new(bpf_map__fd(skel->maps.critical), save_event, &lanes[0], NULL);
    rings[1] = ring_buffer__new(bpf_map__fd(skel->maps.general), save_event, &lanes[1], NULL);
    rings[2] = ring_buffer__new(bpf_map__fd(skel->maps.quarantine), save_event, &lanes[2], NULL);
    rings[3] = ring_buffer__new(bpf_map__fd(skel->maps.quarantine_control), save_control, NULL, NULL);
    if (!rings[0] || !rings[1] || !rings[2] || !rings[3]) { fail(EINVAL, 0); goto done; }
    for (int i = 0; i < LANE_COUNT; i++) {
        int error = pthread_create(&writers[i], NULL, write_lane, &lanes[i]);
        if (error) { fail(error, 0); goto done; }
        writers_started[i] = 1;
    }
    if (sensor_bpf__attach(skel)) { fail(EINVAL, 0); goto done; }
    for (int i = 0; i < RING_COUNT; i++) drain.rings[i] = rings[i];
    error = pthread_create(&drain_thread, NULL, drain_rings, &drain);
    if (error) { fail(error, 0); goto done; }
    drain_started = 1;
    if (snapshot(skel, "RUNNING", 1)) { fail(errno, 0); goto done; }
    uint64_t last_snapshot = now_ms();
    while (!stopping && !failed()) {
        uint64_t now = now_ms();
        if (now - last_snapshot >= 1000) {
            if (snapshot(skel, "RUNNING", 1)) { fail(errno, 0); break; }
            last_snapshot = now;
        }
        usleep(10000);
    }
done:
    if (skel) sensor_bpf__detach(skel);
    pthread_mutex_lock(&state_lock);
    input_done = 1;
    pthread_mutex_unlock(&state_lock);
    if (drain_started) pthread_join(drain_thread, NULL);
    queues_close();
    for (int i = 0; i < LANE_COUNT; i++) if (writers_started[i]) pthread_join(writers[i], NULL);
    /* Writers drain accepted queues and publish fdatasync boundaries before the
     * final snapshot. A failed lane can retain unappended admitted events. */
    for (int i = 0; i < LANE_COUNT; i++) {
        if (lanes[i].file && fclose(lanes[i].file)) fail(errno, 1);
        lanes[i].file = NULL;
    }
    for (int i = 0; i < RING_COUNT; i++) ring_buffer__free(rings[i]);
    if (metadata.started) {
        meta_wait_idle();
        if (loaded && snapshot(skel, failed() ? "FAILED" : "STOPPED", 1)) fail(errno, 0);
    }
    meta_close();
    if (metadata.started) pthread_join(metadata_thread, NULL);
    meta_destroy();
    if (loaded && snapshot(skel, failed() ? "FAILED" : "STOPPED", 0)) fail(errno, 0);
    for (int i = 0; i < LANE_COUNT; i++) {
        queue_destroy(&lanes[i]);
    }
    sensor_bpf__destroy(skel);
    if (dirfd_ >= 0) close(dirfd_);
    if (failure) fprintf(stderr, "collector failed: %s (%d)\n", strerror(failure), failure);
    return failure ? 1 : 0;
}
