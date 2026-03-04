#include <android/log.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdarg>
#include <dlfcn.h>
#include "zygisk.hpp"
#include "hooks.h"

#define LOG_TAG "ZygiskTelemetrySnifferNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

zygisk::Api* g_api = nullptr;

// Original function pointers
static int (*old_open)(const char* pathname, int flags, ...);
static ssize_t (*old_read)(int fd, void* buf, size_t count);
static int (*old_stat)(const char* pathname, struct stat* statbuf);
static int (*old_execve)(const char* pathname, char* const argv[], char* const envp[]);
static int (*old___system_property_get)(const char* name, char* value);
static void* (*old_dlopen)(const char* filename, int flag);
static void* (*old_android_dlopen_ext)(const char* filename, int flag, const void* extinfo);

int my_open(const char* pathname, int flags, ...);
ssize_t my_read(int fd, void* buf, size_t count);
int my_stat(const char* pathname, struct stat* statbuf);
int my_execve(const char* pathname, char* const argv[], char* const envp[]);
int my___system_property_get(const char* name, char* value);

#include <mutex>
#include <cstring>

std::mutex g_hook_mutex;

// Helper to hook a loaded library
void applyHooksToLibrary(const char* libname) {
    if (g_api) {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        g_api->pltHookRegister(libname, "open", (void*)my_open, (void**)&old_open);
        g_api->pltHookRegister(libname, "read", (void*)my_read, (void**)&old_read);
        g_api->pltHookRegister(libname, "stat", (void*)my_stat, (void**)&old_stat);
        g_api->pltHookRegister(libname, "execve", (void*)my_execve, (void**)&old_execve);
        g_api->pltHookRegister(libname, "__system_property_get", (void*)my___system_property_get, (void**)&old___system_property_get);
        g_api->pltHookCommit();
        LOGI("Applied native hooks to %s", libname ? libname : "all libraries");
    }
}

// Hooked dlopen
void* my_dlopen(const char* filename, int flag) {
    void* handle = old_dlopen(filename, flag);
    if (handle != nullptr && filename != nullptr) {
        LOGI("dlopen called for library: %s", filename);
        // Apply hooks to the newly loaded library
        applyHooksToLibrary(filename);
    }
    return handle;
}

// Hooked android_dlopen_ext
void* my_android_dlopen_ext(const char* filename, int flag, const void* extinfo) {
    void* handle = old_android_dlopen_ext(filename, flag, extinfo);
    if (handle != nullptr && filename != nullptr) {
        LOGI("android_dlopen_ext called for library: %s", filename);
        // Apply hooks to the newly loaded library
        applyHooksToLibrary(filename);
    }
    return handle;
}

// Hooked open
// Forward declare
extern void notify_binder_fd_opened(int fd);

int my_open(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = -1;
    if (flags & O_CREAT) {
        fd = old_open(pathname, flags, mode);
    } else {
        fd = old_open(pathname, flags);
    }

    if (pathname != nullptr && fd >= 0) {
        if (strcmp(pathname, "/dev/binder") == 0 || strcmp(pathname, "/dev/hwbinder") == 0) {
            notify_binder_fd_opened(fd);
        } else if (strncmp(pathname, "/sys/class/net/", 15) == 0 ||
                   strncmp(pathname, "/proc/net/", 10) == 0 ||
                   strstr(pathname, "mac") != nullptr) {
            LOGI("Tracking file opened: %s", pathname);
        }
    }

    return fd;
}

// Hooked read
ssize_t my_read(int fd, void* buf, size_t count) {
    // Optionally log read size/FD. This could be very noisy if done generally.
    // LOGI("read called with fd: %d, count: %zu", fd, count);
    return old_read(fd, buf, count);
}

// Hooked stat
int my_stat(const char* pathname, struct stat* statbuf) {
    if (pathname != nullptr) {
        LOGI("stat called with path: %s", pathname);
    }
    return old_stat(pathname, statbuf);
}

// Hooked execve
int my_execve(const char* pathname, char* const argv[], char* const envp[]) {
    if (pathname != nullptr) {
        LOGI("execve called with path: %s", pathname);
    }
    return old_execve(pathname, argv, envp);
}

// Hooked __system_property_get
int my___system_property_get(const char* name, char* value) {
    if (name != nullptr) {
        LOGI("__system_property_get called with name: %s", name);
    }
    return old___system_property_get(name, value);
}

void initNativeHooks(zygisk::Api* api) {
    g_api = api;

    // We utilize Zygisk's built-in PLT hooking function.
    // Intercept calls inside libc and existing libraries
    api->pltHookRegister(".*", "open", (void*)my_open, (void**)&old_open);
    api->pltHookRegister(".*", "read", (void*)my_read, (void**)&old_read);
    api->pltHookRegister(".*", "stat", (void*)my_stat, (void**)&old_stat);
    api->pltHookRegister(".*", "execve", (void*)my_execve, (void**)&old_execve);
    api->pltHookRegister(".*", "__system_property_get", (void*)my___system_property_get, (void**)&old___system_property_get);

    // Hook library loading functions to apply hooks to dynamically loaded libraries
    api->pltHookRegister(".*", "dlopen", (void*)my_dlopen, (void**)&old_dlopen);
    api->pltHookRegister(".*", "android_dlopen_ext", (void*)my_android_dlopen_ext, (void**)&old_android_dlopen_ext);

    if (api->pltHookCommit()) {
        LOGI("Successfully committed native PLT hooks.");
    } else {
        LOGI("Failed to commit native PLT hooks.");
    }
}
