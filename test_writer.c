/* Synthetic userspace queue/writer tests. Never loads BPF or emits workloads. */
#define main collector_program_main
#include "collector.c"
#undef main
#include <assert.h>

static struct eq_event event_for(int lane, uint64_t sequence) {
    struct eq_event event = {.magic = EQ_MAGIC, .schema = EQ_SCHEMA, .kind = EQ_OPEN,
        .priority = lane == 1 ? EQ_NORMAL : EQ_CRITICAL, .sequence = sequence,
        .quality = lane == 1 ? 0 : (1u << EQ_RULE_SHIFT)};
    if (lane == 2) event.quality |= EQ_QUARANTINED | EQ_Q_PERIODIC;
    return event;
}
static void setup(size_t capacity) {
    assert(!failed());
    max_bytes = 1024 * 1024;
    general_limit = max_bytes - 240;
    quarantine_limit = general_limit;
    for (int i = 0; i < LANE_COUNT; i++) {
        lanes[i].file = tmpfile();
        assert(lanes[i].file && !queue_init(&lanes[i], capacity));
    }
}
static void reset(void) {
    for (int i = 0; i < LANE_COUNT; i++) {
        queue_destroy(&lanes[i]);
        if (lanes[i].file) fclose(lanes[i].file);
    }
    memset(lanes, 0, sizeof(lanes));
    failure = input_done = 0;
    persist_failed = general_quota_drop = 0;
    quarantine_storage_drop = stream_storage_overflow = 0; quarantine_limit = 0; stream_storage_complete = 1; memset(stream_storage, 0, sizeof(stream_storage)); memset(&fallback_storage, 0, sizeof(fallback_storage));
}
static void start_writers(pthread_t workers[LANE_COUNT]) {
    for (int i = 0; i < LANE_COUNT; i++) assert(!pthread_create(&workers[i], NULL, write_lane, &lanes[i]));
}
static void finish_writers(pthread_t workers[LANE_COUNT]) {
    queues_close();
    for (int i = 0; i < LANE_COUNT; i++) assert(!pthread_join(workers[i], NULL));
}
static void expect_record(int lane, uint64_t sequence) {
    struct eq_record record;
    assert(fread(&record, sizeof(record), 1, lanes[lane].file) == 1);
    assert(record.event.sequence == sequence && !record.reserved);
    assert(record.crc32 == crc32(0, (void *)&record.event, sizeof(record.event)));
}
static void test_overflow_order_shutdown(void) {
    setup(2);
    for (uint64_t seq = 1; seq <= 3; seq++) {
        struct eq_event event = event_for(0, seq);
        assert(!save_event(&lanes[0], &event, sizeof(event)));
    }
    assert(lanes[0].observed == 3 && lanes[0].admitted == 2);
    assert(lanes[0].queue_overflow == 1 && lanes[0].high_water == 2);
    assert(lanes[0].received == 0 && lanes[0].durable == 0);
    pthread_t workers[LANE_COUNT]; start_writers(workers); finish_writers(workers);
    assert(!failed() && lanes[0].received == 2 && lanes[0].durable == 480);
    assert(!lanes[0].count && !lanes[0].in_flight && lanes[0].closed);
    rewind(lanes[0].file); expect_record(0, 1); expect_record(0, 2);
    assert(fgetc(lanes[0].file) == EOF);
    struct eq_event event = event_for(0, 4);
    assert(save_event(&lanes[0], &event, sizeof(event)) == -EPIPE);
    reset();
}
static void test_quota_includes_pending(void) {
    setup(8);
    general_limit = 240; max_bytes = 720;
    struct eq_event general = event_for(1, 1), critical = event_for(0, 2);
    assert(!save_event(&lanes[1], &general, sizeof(general)));
    assert(!save_event(&lanes[1], &general, sizeof(general)));
    assert(general_quota_drop == 1 && lanes[1].admitted == 1 && lanes[1].observed == 2);
    assert(!save_event(&lanes[0], &critical, sizeof(critical)));
    critical.sequence++;
    assert(!save_event(&lanes[0], &critical, sizeof(critical)));
    assert(save_event(&lanes[0], &critical, sizeof(critical)) == -EFBIG);
    assert(persist_failed == 1 && lanes[0].received == 0 && lanes[1].received == 0);
    pthread_t workers[LANE_COUNT]; start_writers(workers); finish_writers(workers);
    assert(lanes[0].durable == 480 && lanes[1].durable == 240);
    reset();
}
struct producer { int lane, result; pthread_barrier_t *barrier; };
static void *produce_one(void *ctx) {
    struct producer *producer = ctx;
    struct eq_event event = event_for(producer->lane, 1);
    pthread_barrier_wait(producer->barrier);
    producer->result = save_event(&lanes[producer->lane], &event, sizeof(event));
    return NULL;
}
static void test_atomic_quota(void) {
    setup(2);
    max_bytes = general_limit = 240;
    pthread_barrier_t barrier;
    assert(!pthread_barrier_init(&barrier, NULL, 2));
    struct producer producers[2] = {{.lane = 0, .barrier = &barrier}, {.lane = 1, .barrier = &barrier}};
    pthread_t threads[2];
    for (int i = 0; i < 2; i++) assert(!pthread_create(&threads[i], NULL, produce_one, &producers[i]));
    for (int i = 0; i < 2; i++) assert(!pthread_join(threads[i], NULL));
    assert(lanes[0].admitted + lanes[1].admitted == 1);
    assert((producers[0].result == 0 && producers[1].result == -EFBIG) ||
           (producers[1].result == 0 && producers[0].result == -EFBIG));
    assert(persist_failed == 1);
    pthread_barrier_destroy(&barrier);
    reset();
}
static void test_invalid_event(void) {
    setup(2);
    struct eq_event event = event_for(0, 1);
    assert(save_event(&lanes[1], &event, sizeof(event)) == -EPROTO);
    assert(!lanes[1].observed && !lanes[1].admitted);
    reset();
    setup(2); event = event_for(1, 1); event.kind = 99;
    assert(save_event(&lanes[1], &event, sizeof(event)) == -EPROTO);
    reset();
}
static void test_persist_failure(void) {
    setup(2);
    fclose(lanes[1].file); lanes[1].file = fopen("/dev/full", "wb");
    assert(lanes[1].file);
    struct eq_event event = event_for(1, 1);
    assert(!save_event(&lanes[1], &event, sizeof(event)));
    pthread_t workers[LANE_COUNT]; start_writers(workers); finish_writers(workers);
    assert(failed() && persist_failed >= 1 && lanes[1].durable == 0);
    reset();
}
/* A full pipe blocks the general fwrite. Critical still drains and fdatasyncs
 * its own file. Pipe fdatasync then fails explicitly, exercising sync accounting. */
static void test_independent_writers_and_sync_failure(void) {
    setup(2);
    int pipefd[2]; assert(!pipe(pipefd));
    int flags = fcntl(pipefd[1], F_GETFL);
    assert(flags >= 0 && !fcntl(pipefd[1], F_SETFL, flags | O_NONBLOCK));
    char bytes[4096] = {};
    ssize_t written; size_t filled = 0;
    while ((written = write(pipefd[1], bytes, sizeof(bytes))) > 0) filled += written;
    assert(errno == EAGAIN && filled && !fcntl(pipefd[1], F_SETFL, flags));
    fclose(lanes[1].file); lanes[1].file = fdopen(pipefd[1], "wb");
    assert(lanes[1].file && !setvbuf(lanes[1].file, NULL, _IONBF, 0));
    struct eq_event general = event_for(1, 1), critical = event_for(0, 2);
    assert(!save_event(&lanes[1], &general, sizeof(general)));
    pthread_t workers[LANE_COUNT];
    assert(!pthread_create(&workers[1], NULL, write_lane, &lanes[1]));
    int blocked = 0;
    for (int retry = 0; retry < 1000 && !blocked; retry++) {
        pthread_mutex_lock(&state_lock);
        blocked = lanes[1].in_flight;
        pthread_mutex_unlock(&state_lock);
        if (!blocked) usleep(1000);
    }
    assert(blocked);
    assert(!save_event(&lanes[0], &critical, sizeof(critical)));
    assert(!pthread_create(&workers[0], NULL, write_lane, &lanes[0]));
    queues_close();
    assert(!pthread_join(workers[0], NULL));
    pthread_mutex_lock(&state_lock);
    assert(lanes[0].durable == 240 && lanes[1].received == 0 && lanes[1].durable == 0);
    pthread_mutex_unlock(&state_lock);
    while (filled) {
        ssize_t count = read(pipefd[0], bytes, filled < sizeof(bytes) ? filled : sizeof(bytes));
        assert(count > 0); filled -= count;
    }
    assert(!pthread_join(workers[1], NULL));
    assert(failed() == EINVAL && persist_failed == 1);
    assert(lanes[1].received == 1 && lanes[1].durable == 0);
    close(pipefd[0]);
    reset();
}
static void test_quarantine_limits_preserve_critical(void) {
    setup(2); max_bytes = 4096; general_limit = 240; quarantine_limit = 240;
    struct eq_event sample = event_for(2, 1), critical = event_for(0, 10);
    sample.cgroup_id = critical.cgroup_id = 7;
    assert(!save_event(&lanes[2], &sample, sizeof(sample)));
    sample.sequence++;
    assert(!save_event(&lanes[2], &sample, sizeof(sample)));
    assert(!failed() && quarantine_storage_drop == 1 && lanes[2].admitted == 1);
    assert(!save_event(&lanes[0], &critical, sizeof(critical)));
    pthread_t workers[LANE_COUNT]; start_writers(workers); finish_writers(workers);
    assert(!failed() && lanes[0].durable == 240 && lanes[2].durable == 240);
    struct stream_storage *storage = storage_for(&sample);
    assert(storage->storage_rejected[1] == 1 && storage->durable[2] == 1 && storage->durable[0] == 1);
    reset();
    setup(1);
    sample = event_for(2, 1); critical = event_for(0, 10);
    assert(!save_event(&lanes[2], &sample, sizeof(sample)));
    sample.sequence++;
    assert(!save_event(&lanes[2], &sample, sizeof(sample)));
    assert(lanes[2].queue_overflow == 1 && !failed());
    assert(!save_event(&lanes[0], &critical, sizeof(critical)));
    start_writers(workers); finish_writers(workers);
    assert(lanes[0].durable == 240 && lanes[2].durable == 240 && !failed());
    reset();
}
static void test_quarantine_counts_sync_boundary(void) {
    setup(4);
    struct eq_event initial = event_for(2, 1), sample = event_for(2, 2);
    initial.quality &= ~EQ_Q_PERIODIC; initial.quality |= EQ_Q_INITIAL;
    initial.cgroup_id = sample.cgroup_id = 42;
    assert(!save_event(&lanes[2], &initial, sizeof(initial)));
    assert(!save_event(&lanes[2], &sample, sizeof(sample)));
    struct stream_storage *storage = storage_for(&initial);
    assert(!storage->appended[1] && !storage->durable[1] && !storage->durable[2]);
    pthread_t workers[LANE_COUNT]; start_writers(workers); finish_writers(workers);
    assert(storage->appended[1] == 1 && storage->appended[2] == 1);
    assert(storage->durable[1] == 1 && storage->durable[2] == 1 && lanes[2].durable == 480);
    rewind(lanes[2].file); expect_record(2, 1); expect_record(2, 2);
    reset();
}
static uint32_t little_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
static void test_metadata_fence_crc_and_overflow(void) {
    setup(2);
    char path[] = "/tmp/mglogwh-meta-XXXXXX";
    assert(mkdtemp(path));
    int previous = open(".", O_DIRECTORY | O_RDONLY);
    assert(previous >= 0 && !chdir(path));
    dirfd_ = open(".", O_DIRECTORY | O_RDONLY); assert(dirfd_ >= 0);
    strcpy(run_id, "00000000-0000-0000-0000-000000000001");
    memset(manifest_sha256, 'a', 64); manifest_sha256[64] = 0;
    memset(config_sha256, 'b', 64); config_sha256[64] = 0;
    strcpy(boot_id, "00000000-0000-0000-0000-000000000002");
    int fd = open("evidence.meta", O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(fd >= 0 && !meta_init(8 * 1024 * 1024, fd));
    struct eq_event event = event_for(0, 42); event.cgroup_id = 7; event.monotonic_ns = 123;
    struct meta_item loss = {.loss = 1, .event = event, .reason = Q_STORAGE_LIMIT, .lane = 2};
    assert(!meta_write(&loss) && !meta_sync());
    assert(metadata.committed == metadata.written && metadata.committed_seq == 1);
    FILE *input = fopen("evidence.meta", "rb"); assert(input);
    unsigned char header[8]; assert(fread(header, 8, 1, input) == 1);
    uint32_t length = little_u32(header), checksum = little_u32(header + 4);
    assert(length > 0 && length <= META_FRAME_MAX);
    char *json = calloc(length + 1, 1); assert(json && fread(json, length, 1, input) == 1);
    assert(checksum == crc32(0, (void *)json, length));
    assert(strstr(json, "\"seq\":42") && strstr(json, "Q_STORAGE_LIMIT") && strstr(json, manifest_sha256));
    free(json); fclose(input);
    input = fopen("evidence.meta.commit", "rb"); assert(input);
    char fence[1024] = {}; assert(fread(fence, 1, sizeof(fence) - 1, input) > 0); fclose(input);
    assert(strstr(fence, "\"journal_seq\":1") && strstr(fence, run_id));
    const char *seal = "{\"record_type\":\"seal\",\"state\":\"STOPPED\",\"durable_offsets\":{\"critical\":0,\"general\":0},\"tenants\":[],\"sequence_snapshot_complete\":true}";
    assert(!publish_snapshot(strdup(seal), strlen(seal), 1, 1));
    assert(metadata.count == 1 && metadata.queue[metadata.head].terminal);
    assert(access("health.json", F_OK) && errno == ENOENT);
    assert(access("health.json.tmp", F_OK) && errno == ENOENT);
    free(metadata.queue[metadata.head].payload);
    memset(&metadata.queue[metadata.head], 0, sizeof(*metadata.queue)); metadata.count = 0;
    uint64_t control_offset = metadata.committed;
    struct eq_quarantine_control control = {.key = {.cgroup_id = 7, .rule_id = 1, .kind = EQ_OPEN},
        .transition = EQ_Q_ENTER, .reason = EQ_Q_HIGH_RATE, .monotonic_ns = 123,
        .transition_sequence = 42, .threshold_eps = 10000, .observed_eps = 20000, .duration_ms = 3000,
        .episode = {.episode_id = 1, .first_sequence = 42, .last_sequence = 42, .tracking_complete = 1}};
    assert(!save_control(NULL, &control, sizeof(control)));
    assert(metadata.count == 1 && metadata.committed == control_offset);
    struct meta_item control_item = metadata.queue[metadata.head];
    memset(&metadata.queue[metadata.head], 0, sizeof(*metadata.queue)); metadata.count = 0;
    assert(!meta_write(&control_item) && !meta_sync() && metadata.committed_seq == 2);
    input = fopen("evidence.meta", "rb"); assert(input && !fseek(input, control_offset, SEEK_SET));
    assert(fread(header, 8, 1, input) == 1); length = little_u32(header); checksum = little_u32(header + 4);
    json = calloc(length + 1, 1); assert(json && fread(json, length, 1, input) == 1);
    assert(checksum == crc32(0, (void *)json, length) && strstr(json, "quarantine_enter") && strstr(json, "HIGH_RATE"));
    free(json); fclose(input);
    const char *checkpoint = "{\"record_type\":\"checkpoint\",\"durable_offsets\":{\"critical\":0,\"general\":0}}";
    assert(!meta_enqueue(strdup(checkpoint), strlen(checkpoint), 0));
    assert(!meta_enqueue(strdup(checkpoint), strlen(checkpoint), 0));
    assert(metadata.checkpoint_pending == 1 && metadata.checkpoint_coalesced == 1 && metadata.count == 1);
    pthread_mutex_lock(&state_lock);
    for (unsigned n = 0; n < META_QUEUE_CAP; n++) loss_locked(&event, Q_STORAGE_LIMIT, 2);
    pthread_mutex_unlock(&state_lock);
    assert(metadata.count == META_QUEUE_CAP && metadata.overflow == 1 && metadata.dropped == 1);
    uint64_t before = metadata.written;
    metadata.max_bytes = META_FRAME_MAX + 8;
    assert(!meta_write(&loss) && metadata.written == before && metadata.dropped == 2);
    struct meta_item terminal = {.payload = (char *)seal, .length = strlen(seal), .terminal = 1};
    assert(!meta_write(&terminal) && !meta_sync() && metadata.committed_seq == 3);
    meta_destroy(); memset(&metadata, 0, sizeof(metadata));
    assert(!publish_snapshot(strdup(seal), strlen(seal), 0, 1));
    assert(!access("health.json", F_OK));
    assert(!unlink("health.json"));
    assert(!unlink("evidence.meta") && !unlink("evidence.meta.commit"));
    close(dirfd_); dirfd_ = -1;
    assert(!fchdir(previous)); close(previous); assert(!rmdir(path));
    reset();
}
int main(void) {
    test_overflow_order_shutdown();
    test_quota_includes_pending();
    test_atomic_quota();
    test_invalid_event();
    test_persist_failure();
    test_independent_writers_and_sync_failure();
    test_quarantine_limits_preserve_critical();
    test_quarantine_counts_sync_boundary();
    test_metadata_fence_crc_and_overflow();
    puts("writer FIFO/quotas/quarantine isolation/durability/control CRC/fence/overflow checks: OK");
    return 0;
}
