/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * This implementation keeps the architecture intentionally small:
 *   - a long-running supervisor reachable over a UNIX domain socket
 *   - clone()-based container launch with PID/UTS/mount isolation
 *   - per-container producer threads feeding a bounded log buffer
 *   - a single logger thread flushing logs to files
 *   - optional integration with /dev/container_monitor when loaded
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 16384
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct child_config {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;
    int log_read_fd;
    int run_wait_fd;
    int producer_joined;
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    char stop_reason[64];
    char log_path[PATH_MAX];
    child_config_t child_cfg;
    pthread_t producer_thread;
    void *child_stack;
    struct container_record *next;
} container_record_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    supervisor_ctx_t *ctx;
    container_record_t *record;
} producer_arg_t;

static volatile sig_atomic_t g_shutdown_requested;
static volatile sig_atomic_t g_sigchld_seen;
static volatile sig_atomic_t g_last_shutdown_signal;

static void reap_children(supervisor_ctx_t *ctx);
static void cleanup_finished_containers(supervisor_ctx_t *ctx);

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static void set_response(control_response_t *resp, int status, const char *fmt, ...)
{
    va_list ap;

    resp->status = status;
    va_start(ap, fmt);
    vsnprintf(resp->message, sizeof(resp->message), fmt, ap);
    va_end(ap);
}

static int send_response_fd(int fd, const control_response_t *resp)
{
    size_t remaining = sizeof(*resp);
    const char *ptr = (const char *)resp;

    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ptr += (size_t)written;
        remaining -= (size_t)written;
    }

    return 0;
}

static int recv_request_fd(int fd, control_request_t *req)
{
    size_t received = 0;
    char *ptr = (char *)req;

    while (received < sizeof(*req)) {
        ssize_t rc = read(fd, ptr + received, sizeof(*req) - received);
        if (rc == 0)
            return -1;
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        received += (size_t)rc;
    }

    req->container_id[sizeof(req->container_id) - 1] = '\0';
    req->rootfs[sizeof(req->rootfs) - 1] = '\0';
    req->command[sizeof(req->command) - 1] = '\0';
    return 0;
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (!buffer->shutting_down && buffer->count == LOG_BUFFER_CAPACITY)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return 0;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 1;
}

static int ensure_logs_dir(void)
{
    if (mkdir(LOG_DIR, 0755) < 0 && errno != EEXIST) {
        perror("mkdir logs");
        return -1;
    }
    return 0;
}

static container_record_t *find_container_by_id_locked(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *cur;

    for (cur = ctx->containers; cur; cur = cur->next) {
        if (strncmp(cur->id, id, sizeof(cur->id)) == 0)
            return cur;
    }

    return NULL;
}

static container_record_t *find_container_by_pid_locked(supervisor_ctx_t *ctx, pid_t pid)
{
    container_record_t *cur;

    for (cur = ctx->containers; cur; cur = cur->next) {
        if (cur->host_pid == pid)
            return cur;
    }

    return NULL;
}

static int container_is_active(const container_record_t *record)
{
    return record->host_pid > 0 &&
           (record->state == CONTAINER_STARTING || record->state == CONTAINER_RUNNING);
}

static container_record_t *find_active_container_by_rootfs_locked(supervisor_ctx_t *ctx,
                                                                  const char *rootfs)
{
    container_record_t *cur;

    for (cur = ctx->containers; cur; cur = cur->next) {
        if (!container_is_active(cur))
            continue;

        if (strncmp(cur->rootfs, rootfs, sizeof(cur->rootfs)) == 0)
            return cur;
    }

    return NULL;
}

static int register_with_monitor(int monitor_fd,
                                 const char *container_id,
                                 pid_t host_pid,
                                 unsigned long soft_limit_bytes,
                                 unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    if (monitor_fd < 0)
        return 0;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

static int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    if (monitor_fd < 0)
        return 0;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

static void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = arg;
    log_item_t item;

    while (1) {
        int rc = bounded_buffer_pop(&ctx->log_buffer, &item);

        if (rc == 0)
            break;
        if (rc < 0)
            continue;

        {
            char path[PATH_MAX];
            int log_fd;

            snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
            log_fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
            if (log_fd < 0) {
                perror("open log");
                continue;
            }

            if (write(log_fd, item.data, item.length) < 0)
                perror("write log");

            close(log_fd);
        }
    }

    return NULL;
}

static void *container_log_producer(void *arg)
{
    producer_arg_t *producer = arg;
    supervisor_ctx_t *ctx = producer->ctx;
    container_record_t *record = producer->record;
    char buf[LOG_CHUNK_SIZE];

    for (;;) {
        ssize_t n = read(record->log_read_fd, buf, sizeof(buf));
        log_item_t item;

        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        memset(&item, 0, sizeof(item));
        strncpy(item.container_id, record->id, sizeof(item.container_id) - 1);
        item.length = (size_t)n;
        memcpy(item.data, buf, (size_t)n);
        if (bounded_buffer_push(&ctx->log_buffer, &item) != 0)
            break;
    }

    close(record->log_read_fd);
    record->log_read_fd = -1;
    free(producer);
    return NULL;
}

static int child_fn(void *arg)
{
    child_config_t *config = arg;

    if (setpriority(PRIO_PROCESS, 0, config->nice_value) < 0)
        perror("setpriority");

    if (sethostname(config->id, strlen(config->id)) < 0)
        perror("sethostname");

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        perror("mount private");

    if (chdir(config->rootfs) < 0) {
        perror("chdir rootfs");
        return 1;
    }

    if (chroot(".") < 0) {
        perror("chroot");
        return 1;
    }

    if (chdir("/") < 0) {
        perror("chdir /");
        return 1;
    }

    if (mkdir("/proc", 0555) < 0 && errno != EEXIST) {
        perror("mkdir /proc");
        return 1;
    }

    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        perror("mount /proc");

    if (dup2(config->log_write_fd, STDOUT_FILENO) < 0 ||
        dup2(config->log_write_fd, STDERR_FILENO) < 0) {
        perror("dup2");
        return 1;
    }

    close(config->log_write_fd);

    execl("/bin/sh", "sh", "-c", config->command, (char *)NULL);
    perror("exec /bin/sh");
    return 127;
}

static void finalize_run_waiter(container_record_t *record)
{
    if (record->run_wait_fd >= 0) {
        control_response_t resp;
        int status_code = record->exit_code;

        if (record->exit_signal != 0)
            status_code = 128 + record->exit_signal;

        set_response(&resp,
                     status_code,
                     "Container %s finished state=%s exit_code=%d signal=%d reason=%s",
                     record->id,
                     state_to_string(record->state),
                     record->exit_code,
                     record->exit_signal,
                     record->stop_reason);
        send_response_fd(record->run_wait_fd, &resp);
        close(record->run_wait_fd);
        record->run_wait_fd = -1;
    }
}

static void reap_children(supervisor_ctx_t *ctx)
{
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        container_record_t *record;

        pthread_mutex_lock(&ctx->metadata_lock);
        record = find_container_by_pid_locked(ctx, pid);
        if (record) {
            record->host_pid = -1;
            record->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            record->exit_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;

            if (record->stop_requested) {
                record->state = CONTAINER_STOPPED;
                strncpy(record->stop_reason, "manual_stop", sizeof(record->stop_reason) - 1);
            } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
                record->state = CONTAINER_KILLED;
                strncpy(record->stop_reason, "hard_limit_killed", sizeof(record->stop_reason) - 1);
            } else if (WIFSIGNALED(status)) {
                record->state = CONTAINER_KILLED;
                strncpy(record->stop_reason, "signaled", sizeof(record->stop_reason) - 1);
            } else {
                record->state = CONTAINER_EXITED;
                strncpy(record->stop_reason, "normal_exit", sizeof(record->stop_reason) - 1);
            }

            unregister_from_monitor(ctx->monitor_fd, record->id, pid);
            finalize_run_waiter(record);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }
}

static int start_container(supervisor_ctx_t *ctx,
                           const control_request_t *req,
                           int run_wait_fd,
                           control_response_t *resp)
{
    container_record_t *record;
    producer_arg_t *producer;
    int pipe_fds[2];
    int clone_flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD;
    pid_t child_pid;

    if (req->container_id[0] == '\0' || req->rootfs[0] == '\0' || req->command[0] == '\0') {
        set_response(resp, 1, "Container id, rootfs, and command are required.");
        return 1;
    }

    if (ensure_logs_dir() != 0) {
        set_response(resp, 1, "Failed to create log directory.");
        return 1;
    }

    if (access(req->rootfs, F_OK) != 0) {
        set_response(resp, 1, "Rootfs not found: %s", req->rootfs);
        return 1;
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container_by_id_locked(ctx, req->container_id)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        set_response(resp, 1, "Container id already exists: %s", req->container_id);
        return 1;
    }
    if (find_active_container_by_rootfs_locked(ctx, req->rootfs)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        set_response(resp,
                     1,
                     "Rootfs already in use by a live container: %s",
                     req->rootfs);
        return 1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    record = calloc(1, sizeof(*record));
    if (!record) {
        set_response(resp, 1, "calloc failed: %s", strerror(errno));
        return 1;
    }

    record->log_read_fd = -1;
    record->run_wait_fd = run_wait_fd;
    record->started_at = time(NULL);
    record->state = CONTAINER_STARTING;
    record->soft_limit_bytes = req->soft_limit_bytes;
    record->hard_limit_bytes = req->hard_limit_bytes;
    strncpy(record->id, req->container_id, sizeof(record->id) - 1);
    strncpy(record->rootfs, req->rootfs, sizeof(record->rootfs) - 1);
    strncpy(record->command, req->command, sizeof(record->command) - 1);
    snprintf(record->log_path, sizeof(record->log_path), "%s/%s.log", LOG_DIR, record->id);
    strncpy(record->stop_reason, "running", sizeof(record->stop_reason) - 1);

    {
        int log_fd = open(record->log_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (log_fd < 0) {
            set_response(resp, 1, "Failed to initialize log file %s: %s", record->log_path, strerror(errno));
            free(record);
            return 1;
        }
        close(log_fd);
    }

    if (pipe(pipe_fds) < 0) {
        set_response(resp, 1, "pipe failed: %s", strerror(errno));
        free(record);
        return 1;
    }

    memset(&record->child_cfg, 0, sizeof(record->child_cfg));
    strncpy(record->child_cfg.id, record->id, sizeof(record->child_cfg.id) - 1);
    strncpy(record->child_cfg.rootfs, record->rootfs, sizeof(record->child_cfg.rootfs) - 1);
    strncpy(record->child_cfg.command, record->command, sizeof(record->child_cfg.command) - 1);
    record->child_cfg.nice_value = req->nice_value;
    record->child_cfg.log_write_fd = pipe_fds[1];

    record->child_stack = malloc(STACK_SIZE);
    if (!record->child_stack) {
        set_response(resp, 1, "malloc child stack failed: %s", strerror(errno));
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        free(record);
        return 1;
    }

    child_pid = clone(child_fn,
                      (char *)record->child_stack + STACK_SIZE,
                      clone_flags,
                      &record->child_cfg);
    if (child_pid < 0) {
        set_response(resp, 1, "clone failed: %s", strerror(errno));
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        free(record->child_stack);
        free(record);
        return 1;
    }

    close(pipe_fds[1]);
    record->host_pid = child_pid;
    record->log_read_fd = pipe_fds[0];
    record->state = CONTAINER_RUNNING;

    producer = calloc(1, sizeof(*producer));
    if (!producer) {
        kill(child_pid, SIGKILL);
        close(pipe_fds[0]);
        free(record->child_stack);
        free(record);
        set_response(resp, 1, "calloc producer failed: %s", strerror(errno));
        return 1;
    }

    producer->ctx = ctx;
    producer->record = record;
    if (pthread_create(&record->producer_thread, NULL, container_log_producer, producer) != 0) {
        kill(child_pid, SIGKILL);
        close(pipe_fds[0]);
        free(producer);
        free(record->child_stack);
        free(record);
        set_response(resp, 1, "pthread_create failed for log producer.");
        return 1;
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    record->next = ctx->containers;
    ctx->containers = record;
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (register_with_monitor(ctx->monitor_fd,
                              record->id,
                              record->host_pid,
                              record->soft_limit_bytes,
                              record->hard_limit_bytes) < 0) {
        fprintf(stderr,
                "[mini_runtime] warning: failed to register %s with monitor: %s\n",
                record->id,
                strerror(errno));
    }

    if (run_wait_fd < 0) {
        set_response(resp,
                     0,
                     "Started container %s pid=%d log=%s",
                     record->id,
                     record->host_pid,
                     record->log_path);
    }
    return 0;
}

static void format_ps_locked(supervisor_ctx_t *ctx, control_response_t *resp)
{
    container_record_t *cur;
    size_t used = 0;

    used += (size_t)snprintf(resp->message + used,
                             sizeof(resp->message) - used,
                             "ID\tPID\tSTATE\tSOFT_MIB\tHARD_MIB\tSTARTED\tREASON\tLOG\n");

    for (cur = ctx->containers; cur && used < sizeof(resp->message); cur = cur->next) {
        struct tm tm_info;
        char when[64];
        localtime_r(&cur->started_at, &tm_info);
        strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tm_info);

        used += (size_t)snprintf(resp->message + used,
                                 sizeof(resp->message) - used,
                                 "%s\t%d\t%s\t%lu\t%lu\t%s\t%s\t%s\n",
                                 cur->id,
                                 cur->host_pid,
                                 state_to_string(cur->state),
                                 cur->soft_limit_bytes >> 20,
                                 cur->hard_limit_bytes >> 20,
                                 when,
                                 cur->stop_reason,
                                 cur->log_path);
    }

    resp->status = 0;
}

static int handle_logs(supervisor_ctx_t *ctx,
                       const control_request_t *req,
                       control_response_t *resp)
{
    char path[PATH_MAX];
    int fd;
    ssize_t n;

    (void)ctx;

    snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, req->container_id);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_response(resp, 1, "Could not open log file: %s", path);
        return 1;
    }

    n = read(fd, resp->message, sizeof(resp->message) - 1);
    if (n < 0) {
        close(fd);
        set_response(resp, 1, "Failed to read log file: %s", strerror(errno));
        return 1;
    }

    resp->message[n] = '\0';
    resp->status = 0;
    close(fd);
    return 0;
}

static int handle_stop(supervisor_ctx_t *ctx,
                       const control_request_t *req,
                       control_response_t *resp)
{
    container_record_t *record;
    int attempts;

    pthread_mutex_lock(&ctx->metadata_lock);
    record = find_container_by_id_locked(ctx, req->container_id);
    if (!record) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        set_response(resp, 1, "No such container: %s", req->container_id);
        return 1;
    }

    if (!container_is_active(record)) {
        set_response(resp, 0, "%s is already %s", req->container_id, state_to_string(record->state));
        pthread_mutex_unlock(&ctx->metadata_lock);
        return 0;
    }

    record->stop_requested = 1;
    if (record->host_pid > 0 && kill(record->host_pid, SIGTERM) < 0 && errno != ESRCH) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        set_response(resp, 1, "Failed to signal %s: %s", req->container_id, strerror(errno));
        return 1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    for (attempts = 0; attempts < 20; attempts++) {
        usleep(100000);
        reap_children(ctx);

        pthread_mutex_lock(&ctx->metadata_lock);
        record = find_container_by_id_locked(ctx, req->container_id);
        if (!record || record->host_pid <= 0) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            cleanup_finished_containers(ctx);
            set_response(resp, 0, "Stopped %s", req->container_id);
            return 0;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }

    set_response(resp, 0, "Stop requested for %s", req->container_id);
    return 0;
}

static void cleanup_finished_containers(supervisor_ctx_t *ctx)
{
    container_record_t *cur;

    pthread_mutex_lock(&ctx->metadata_lock);
    cur = ctx->containers;
    while (cur) {
        if (cur->host_pid <= 0 && !cur->producer_joined) {
            pthread_t producer_thread = cur->producer_thread;

            cur->producer_joined = 1;
            pthread_mutex_unlock(&ctx->metadata_lock);
            pthread_join(producer_thread, NULL);
            pthread_mutex_lock(&ctx->metadata_lock);
            cur = ctx->containers;
            continue;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);
}

static void signal_handler(int signo)
{
    if (signo == SIGCHLD)
        g_sigchld_seen = 1;
    else {
        g_last_shutdown_signal = signo;
        g_shutdown_requested = 1;
    }
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) < 0)
        return -1;
    if (sigaction(SIGINT, &sa, NULL) < 0)
        return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return -1;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static int create_server_socket(void)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    unlink(CONTROL_PATH);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        close(fd);
        unlink(CONTROL_PATH);
        return -1;
    }

    return fd;
}

static void drain_and_shutdown(supervisor_ctx_t *ctx)
{
    container_record_t *cur;

    pthread_mutex_lock(&ctx->metadata_lock);
    for (cur = ctx->containers; cur; cur = cur->next) {
        if (cur->host_pid > 0) {
            cur->stop_requested = 1;
            kill(cur->host_pid, SIGTERM);
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    sleep(1);
    reap_children(ctx);

    pthread_mutex_lock(&ctx->metadata_lock);
    for (cur = ctx->containers; cur; cur = cur->next) {
        if (cur->host_pid > 0)
            kill(cur->host_pid, SIGKILL);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    sleep(1);
    reap_children(ctx);
    bounded_buffer_begin_shutdown(&ctx->log_buffer);
    pthread_join(ctx->logger_thread, NULL);

    pthread_mutex_lock(&ctx->metadata_lock);
    cur = ctx->containers;
    ctx->containers = NULL;
    pthread_mutex_unlock(&ctx->metadata_lock);

    while (cur) {
        container_record_t *next = cur->next;
        if (cur->run_wait_fd >= 0) {
            control_response_t resp;
            set_response(&resp, 1, "Supervisor shutting down before %s completed", cur->id);
            send_response_fd(cur->run_wait_fd, &resp);
            close(cur->run_wait_fd);
            cur->run_wait_fd = -1;
        }
        if (cur->log_read_fd >= 0)
            close(cur->log_read_fd);
        if (!cur->producer_joined)
            pthread_join(cur->producer_thread, NULL);
        free(cur->child_stack);
        free(cur);
        cur = next;
    }
}

static int handle_client(supervisor_ctx_t *ctx, int client_fd)
{
    control_request_t req;
    control_response_t resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    if (recv_request_fd(client_fd, &req) != 0) {
        close(client_fd);
        return -1;
    }

    switch (req.kind) {
    case CMD_START:
        if (start_container(ctx, &req, -1, &resp) == 0)
            send_response_fd(client_fd, &resp);
        else
            send_response_fd(client_fd, &resp);
        close(client_fd);
        break;
    case CMD_RUN:
        if (start_container(ctx, &req, client_fd, &resp) != 0) {
            send_response_fd(client_fd, &resp);
            close(client_fd);
        }
        break;
    case CMD_PS:
        pthread_mutex_lock(&ctx->metadata_lock);
        format_ps_locked(ctx, &resp);
        pthread_mutex_unlock(&ctx->metadata_lock);
        send_response_fd(client_fd, &resp);
        close(client_fd);
        break;
    case CMD_LOGS:
        handle_logs(ctx, &req, &resp);
        send_response_fd(client_fd, &resp);
        close(client_fd);
        break;
    case CMD_STOP:
        handle_stop(ctx, &req, &resp);
        send_response_fd(client_fd, &resp);
        close(client_fd);
        break;
    default:
        set_response(&resp, 1, "Unsupported command.");
        send_response_fd(client_fd, &resp);
        close(client_fd);
        break;
    }

    return 0;
}

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct pollfd pfd;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;
    (void)rootfs;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (ensure_logs_dir() != 0) {
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        fprintf(stderr,
                "[mini_runtime] warning: /dev/container_monitor unavailable (%s). "
                "Continuing without kernel memory enforcement.\n",
                strerror(errno));
    }

    ctx.server_fd = create_server_socket();
    if (ctx.server_fd < 0) {
        perror("create_server_socket");
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (install_signal_handlers() < 0) {
        perror("sigaction");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx) != 0) {
        perror("pthread_create logger");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    fprintf(stderr, "[mini_runtime] supervisor ready on %s\n", CONTROL_PATH);

    pfd.fd = ctx.server_fd;
    pfd.events = POLLIN;

    while (!g_shutdown_requested) {
        int poll_rc = poll(&pfd, 1, 500);

        if (g_sigchld_seen) {
            g_sigchld_seen = 0;
            reap_children(&ctx);
            cleanup_finished_containers(&ctx);
        }

        if (poll_rc < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        if (poll_rc == 0)
            continue;

        if (pfd.revents & POLLIN) {
            int client_fd = accept(ctx.server_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR)
                    continue;
                perror("accept");
                break;
            }
            handle_client(&ctx, client_fd);
        }
    }

    if (g_last_shutdown_signal != 0) {
        fprintf(stderr,
                "[mini_runtime] supervisor shutting down after signal %d\n",
                g_last_shutdown_signal);
    }

    drain_and_shutdown(&ctx);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;
    size_t sent = 0;
    const char *ptr = (const char *)req;
    size_t received = 0;
    char *resp_ptr = (char *)&resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    while (sent < sizeof(*req)) {
        ssize_t rc = write(fd, ptr + sent, sizeof(*req) - sent);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            perror("write request");
            close(fd);
            return 1;
        }
        sent += (size_t)rc;
    }

    while (received < sizeof(resp)) {
        ssize_t rc = read(fd, resp_ptr + received, sizeof(resp) - received);
        if (rc == 0)
            break;
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            perror("read response");
            close(fd);
            return 1;
        }
        received += (size_t)rc;
    }

    close(fd);

    if (received < sizeof(resp)) {
        fprintf(stderr, "Incomplete response from supervisor.\n");
        return 1;
    }

    if (req->kind == CMD_PS || req->kind == CMD_LOGS)
        printf("%s", resp.message);
    else if (resp.status == 0)
        printf("%s\n", resp.message);
    else
        fprintf(stderr, "%s\n", resp.message);

    return resp.status;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
