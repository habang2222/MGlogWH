#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* A fixed, paced openat workload.  The counters below are independent of
 * MGlogWH; each requested syscall gets one entry and one result check. */
#define BULK_THREADS 4
#define WORKERS (BULK_THREADS + 2)

struct worker {
    const char *path;
    unsigned rate;
    unsigned seconds;
    int expected_errno;
    uint64_t start_ns;
    uint64_t *latency_ns;
    uint64_t attempts, expected, unexpected, late_over_1ms;
    uint64_t last_end_ns;
};

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void sleep_until(uint64_t ns) {
    struct timespec ts = {.tv_sec = (time_t)(ns / 1000000000ull),
                          .tv_nsec = (long)(ns % 1000000000ull)};
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {}
}

static void *run_worker(void *opaque) {
    struct worker *w = opaque;
    uint64_t count = (uint64_t)w->rate * w->seconds;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t due = w->start_ns + i * 1000000000ull / w->rate;
        sleep_until(due);
        uint64_t before = ns_now();
        errno = 0;
        long fd = syscall(SYS_openat, AT_FDCWD, w->path, O_RDONLY | O_CLOEXEC, 0);
        int saved_errno = errno;
        uint64_t after = ns_now();
        if (fd >= 0) close((int)fd);
        w->latency_ns[i] = after - before;
        w->attempts++;
        if ((w->expected_errno == 0 && fd >= 0) ||
            (w->expected_errno != 0 && fd == -1 && saved_errno == w->expected_errno))
            w->expected++;
        else
            w->unexpected++;
        if (before > due + 1000000ull) w->late_over_1ms++;
        w->last_end_ns = after;
    }
    return NULL;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static double percentile_us(uint64_t *samples, size_t count, unsigned p) {
    if (!count) return 0;
    size_t rank = ((uint64_t)p * count + 99) / 100;
    if (rank < 1) rank = 1;
    if (rank > count) rank = count;
    return (double)samples[rank - 1] / 1000.0;
}

int main(int argc, char **argv) {
    if (argc != 8) {
        fprintf(stderr, "usage: bench_workload BULK_PATH CRITICAL_PATH NORMAL_PATH SECONDS BULK_EPS CRITICAL_EPS NORMAL_EPS\n");
        return 2;
    }
    char *end;
    unsigned value[4];
    for (int i = 0; i < 4; i++) {
        errno = 0;
        unsigned long v = strtoul(argv[i + 4], &end, 10);
        if (errno || *end || v == 0 || v > (i == 0 ? 10ul : 200000ul)) return 2;
        value[i] = (unsigned)v;
    }
    unsigned seconds = value[0], bulk_rate = value[1], critical_rate = value[2], normal_rate = value[3];
    if (bulk_rate % BULK_THREADS || (uint64_t)seconds * (bulk_rate + critical_rate + normal_rate) > 1500000ull)
        return 2;
    struct worker w[WORKERS] = {0};
    pthread_t threads[WORKERS];
    uint64_t start = ns_now() + 300000000ull;
    for (int i = 0; i < WORKERS; i++) {
        w[i].path = i < BULK_THREADS ? argv[1] : i == BULK_THREADS ? argv[2] : argv[3];
        w[i].rate = i < BULK_THREADS ? bulk_rate / BULK_THREADS :
                    i == BULK_THREADS ? critical_rate : normal_rate;
        w[i].seconds = seconds;
        w[i].expected_errno = i < BULK_THREADS ? ENOENT : 0;
        w[i].start_ns = start;
        w[i].latency_ns = calloc((size_t)w[i].rate * seconds, sizeof(uint64_t));
        if (!w[i].latency_ns) return 1;
    }
    for (int i = 0; i < WORKERS; i++) if (pthread_create(&threads[i], NULL, run_worker, &w[i])) return 1;
    uint64_t attempts[3] = {}, expected[3] = {}, unexpected[3] = {}, late[3] = {}, end_ns = start;
    for (int i = 0; i < WORKERS; i++) {
        pthread_join(threads[i], NULL);
        int group = i < BULK_THREADS ? 0 : i == BULK_THREADS ? 1 : 2;
        attempts[group] += w[i].attempts;
        expected[group] += w[i].expected;
        unexpected[group] += w[i].unexpected;
        late[group] += w[i].late_over_1ms;
        if (w[i].last_end_ns > end_ns) end_ns = w[i].last_end_ns;
    }
    size_t total = 0;
    for (int i = 0; i < WORKERS; i++) total += w[i].attempts;
    uint64_t *latency = malloc(total * sizeof(uint64_t));
    if (!latency) return 1;
    size_t at = 0;
    for (int i = 0; i < WORKERS; i++) {
        memcpy(latency + at, w[i].latency_ns, w[i].attempts * sizeof(uint64_t));
        at += w[i].attempts;
        free(w[i].latency_ns);
    }
    qsort(latency, total, sizeof(uint64_t), cmp_u64);
    struct rusage usage = {};
    getrusage(RUSAGE_SELF, &usage);
    double elapsed = (double)(end_ns - start) / 1e9;
    double cpu_s = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 +
                   usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
    printf("{\"scope\":\"DIRECT_SYS_OPENAT_MONOTONIC_WALL_LATENCY_INCLUDES_SCHEDULING\","
           "\"seconds_requested\":%u,\"requested_eps\":%u,\"elapsed_seconds\":%.9f,"
           "\"actual_eps\":%.3f,\"attempts\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
           "\"expected_results\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
           "\"unexpected_results\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
           "\"late_over_1ms\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
           "\"p95_us\":%.3f,\"p99_us\":%.3f,\"workload_cpu_seconds\":%.6f,"
           "\"workload_max_rss_kib\":%ld}\n",
           seconds, bulk_rate + critical_rate + normal_rate, elapsed, (double)total / elapsed,
           attempts[0], attempts[1], attempts[2], expected[0], expected[1], expected[2],
           unexpected[0], unexpected[1], unexpected[2], late[0], late[1], late[2],
           percentile_us(latency, total, 95), percentile_us(latency, total, 99), cpu_s, usage.ru_maxrss);
    free(latency);
    return unexpected[0] || unexpected[1] || unexpected[2] ? 1 : 0;
}
