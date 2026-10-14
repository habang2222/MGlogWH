#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void path(char *out, size_t size, const char *root, const char *part) {
    int n = snprintf(out, size, "%s/%s", root, part);
    if (n < 0 || (size_t)n >= size) abort();
}
static void mkfile(const char *name) {
    int fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0 || write(fd, "fake\n", 5) != 5 || close(fd)) abort();
}
static void exercise(FILE *truth, const char *label, int dirfd, const char *name,
                     const char *shown, int flags) {
    unsigned long long before = ns();
    errno = 0;
    long fd = syscall(SYS_openat, dirfd, name, flags, 0600);
    int saved = errno;
    unsigned long long after = ns();
    struct stat st = {};
    if (fd >= 0 && fstat((int)fd, &st)) abort();
    fprintf(truth, "%s,%d,%s,%d,%ld,%d,%llu,%llu,%llu,%llu\n",
            label, getpid(), shown, flags, fd, saved,
            fd >= 0 ? (unsigned long long)st.st_dev : 0,
            fd >= 0 ? (unsigned long long)st.st_ino : 0, before, after);
    fflush(truth);
    if (fd >= 0) close((int)fd);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--exec-child")) return 0;
    if (argc != 4) return 2;
    const char *root = argv[1], *truth_name = argv[2], *self = argv[3];
    char target[512], denied[512], link[512], created[512], missing[512], longname[512], outside[512];
    char longbase[111];
    memset(longbase, 'x', sizeof(longbase)-1);
    longbase[sizeof(longbase)-1] = 0;
    path(target, sizeof(target), root, "target");
    path(denied, sizeof(denied), root, "denied");
    path(link, sizeof(link), root, "link");
    path(created, sizeof(created), root, "created");
    path(missing, sizeof(missing), root, "missing");
    path(longname, sizeof(longname), root, longbase);
    int outside_length = snprintf(outside, sizeof(outside), "%s-outside", root);
    if (outside_length < 0 || (size_t)outside_length >= sizeof(outside)) abort();
    if (mkdir(root, 0700) && errno != EEXIST) abort();
    mkfile(target); mkfile(denied); mkfile(longname); mkfile(outside);
    if (chmod(denied, 0000)) abort();
    if (symlink("target", link) && errno != EEXIST) abort();
    int dirfd = open(root, O_PATH | O_DIRECTORY);
    if (dirfd < 0 || chdir(root)) abort();
    FILE *truth = fopen(truth_name, "we");
    if (!truth) abort();
    fprintf(truth, "label,pid,path,flags,ret,errno,dev,ino,before_ns,after_ns\n");
    fflush(truth);
    if (prctl(PR_SET_NAME, "mgmatrixprobe", 0, 0, 0)) abort();
    exercise(truth, "absolute_read", AT_FDCWD, target, target, O_RDONLY);
    exercise(truth, "absolute_write", AT_FDCWD, target, target, O_WRONLY);
    exercise(truth, "absolute_read_write", AT_FDCWD, target, target, O_RDWR);
    exercise(truth, "absolute_create", AT_FDCWD, created, created, O_CREAT | O_WRONLY);
    exercise(truth, "absolute_truncate", AT_FDCWD, target, target, O_TRUNC | O_WRONLY);
    exercise(truth, "absolute_o_path", AT_FDCWD, target, target, O_PATH);
    exercise(truth, "relative_cwd", AT_FDCWD, "target", "target", O_RDONLY);
    exercise(truth, "relative_dirfd", dirfd, "target", "target", O_RDONLY);
    exercise(truth, "symlink", AT_FDCWD, link, link, O_RDONLY);
    exercise(truth, "absolute_outside", AT_FDCWD, outside, outside, O_RDONLY);
    exercise(truth, "long_path", AT_FDCWD, longname, longname, O_RDONLY);
    exercise(truth, "permission_denied", AT_FDCWD, denied, denied, O_RDONLY);
    exercise(truth, "missing", AT_FDCWD, missing, missing, O_RDONLY);
    exercise(truth, "bad_pointer", AT_FDCWD, (const char *)1, "<EFAULT pointer>", O_RDONLY);
    char *const child_argv[] = {(char *)self, "--exec-child", NULL};
    char *const envp[] = {"PATH=/usr/bin:/bin", NULL};
    unsigned long long before = ns();
    pid_t child = fork();
    if (child < 0) abort();
    if (!child) {
        syscall(SYS_execve, self, child_argv, envp);
        _exit(111);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) abort();
    fprintf(truth, "exec_success,%d,%s,0,%d,0,0,0,%llu,%llu\n", child, self,
            WIFEXITED(status) ? WEXITSTATUS(status) : -1, before, ns());
    fflush(truth);
    before = ns();
    errno = 0;
    long ret = syscall(SYS_execve, missing, child_argv, envp);
    int saved = errno;
    fprintf(truth, "exec_failure,%d,%s,0,%ld,%d,0,0,%llu,%llu\n",
            getpid(), missing, ret, saved, before, ns());
    fclose(truth); close(dirfd);
    return 0;
}
