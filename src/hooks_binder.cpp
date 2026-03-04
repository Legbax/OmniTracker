#include <android/log.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <cstdarg>
#include <cstdio>
#include <atomic>
#include "zygisk.hpp"
#include "hooks.h"

#define LOG_TAG "ZygiskTelemetrySnifferBinder"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Commands and structs for parsing binder transactions
#define BC_TRANSACTION 0x40406300
#define BR_TRANSACTION 0x80287202

struct binder_transaction_data {
    union {
        size_t handle;
        void* ptr;
    } target;
    void* cookie;
    unsigned int code;
    unsigned int flags;
    pid_t sender_pid;
    uid_t sender_euid;
    size_t data_size;
    size_t offsets_size;
    // Followed by data buffer, omitted for simplicity
};

static int (*old_ioctl)(int fd, unsigned long request, ...);

// We will track the known binder fd globally or per-thread to avoid slow readlink() on every ioctl.
// A simpler robust way for a sniffer without managing thread-locals perfectly is checking atomic FD if it's singleton.
// In Android, an app usually opens /dev/binder once and uses that fd.
std::atomic<int> g_binder_fd{-1};

// Hooked ioctl
int my_ioctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void* argp = va_arg(args, void*);
    va_end(args);

    int cached_fd = g_binder_fd.load(std::memory_order_relaxed);

    // If we haven't found the binder fd yet, do a check.
    if (cached_fd == -1 && request == BINDER_WRITE_READ) {
        char fd_path[256];
        char link_path[256];
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
        ssize_t len = readlink(link_path, fd_path, sizeof(fd_path) - 1);

        if (len != -1) {
            fd_path[len] = '\0';
            if (strcmp(fd_path, "/dev/binder") == 0 || strcmp(fd_path, "/dev/hwbinder") == 0) {
                // We found a binder FD, cache it so future ioctls are O(1)
                g_binder_fd.store(fd, std::memory_order_relaxed);
                cached_fd = fd;
            }
        }
    }

    // Fast path: Only process if it matches the known binder FD and is BINDER_WRITE_READ
    if (fd == cached_fd && request == BINDER_WRITE_READ && argp != nullptr) {
        struct binder_write_read* bwr = (struct binder_write_read*)argp;

        // We can inspect write_buffer for BC_TRANSACTION commands sent from this app to system services
        if (bwr->write_size > 0) {
            unsigned int* cmd_ptr = (unsigned int*)bwr->write_buffer;
            size_t consumed = 0;

            // Simple parsing to find transaction codes.
            // Note: Full parsing requires handling all binder commands properly to advance `consumed`.
            // For a robust sniffer, we'd iterate over cmds based on their known sizes.
            // Here, we check if the first command is BC_TRANSACTION for demonstration.
            if (cmd_ptr && *cmd_ptr == BC_TRANSACTION) {
                struct binder_transaction_data* tr = (struct binder_transaction_data*)(cmd_ptr + 1);
                LOGI("Binder TX OUT: code=%u, data_size=%zu", tr->code, tr->data_size);
                // With transaction code and target handle, we can map to ISms, ITelephony, etc.
            }
        }
    }

    return old_ioctl(fd, request, argp);
}

// Ensure the open hook sets the binder fd early if possible
extern void notify_binder_fd_opened(int fd);
void notify_binder_fd_opened(int fd) {
    g_binder_fd.store(fd, std::memory_order_relaxed);
}

void initBinderHooks(zygisk::Api* api) {
    // Hook ioctl specifically for binder communication parsing
    api->pltHookRegister(".*", "ioctl", (void*)my_ioctl, (void**)&old_ioctl);

    // We assume commit is handled correctly after registering
    if (api->pltHookCommit()) {
        LOGI("Successfully committed Binder PLT hooks.");
    } else {
        LOGI("Failed to commit Binder PLT hooks.");
    }
}
