#pragma once

#include <jni.h>

#define ZYGISK_API_VERSION 4

namespace zygisk {

struct Api {
    // Hooks a JNI function
    void (*hookJniNativeMethods)(JNIEnv* env, const char* className, JNINativeMethod* methods, int numMethods);

    // Hooks a native library function using PLT/GOT hooking
    void (*pltHookRegister)(const char* regex, const char* symbol, void* newFunc, void** oldFunc);

    // Removes a registered PLT hook
    void (*pltHookExclude)(const char* regex, const char* symbol);

    // Commits all registered PLT hooks
    bool (*pltHookCommit)();

    // Gets the path to the companion native library
    int (*connectCompanion)();

    // Request module to be unloaded
    void (*setOption)(int option);
};

struct AppSpecializeArgs {
    int uid;
    int gid;
    int* gids;
    int gids_count;
    int mount_external;
    int seinfo;
    const char* nice_name;
    const char* instruction_set;
    const char* app_data_dir;
};

struct ServerSpecializeArgs {
    int uid;
    int gid;
    int* gids;
    int gids_count;
    int debug_flags;
};

class ModuleBase {
public:
    virtual ~ModuleBase() = default;

    virtual void onLoad(Api* api, JNIEnv* env) {}

    virtual void preAppSpecialize(AppSpecializeArgs* args) {}

    virtual void postAppSpecialize(const AppSpecializeArgs* args) {}

    virtual void preServerSpecialize(ServerSpecializeArgs* args) {}

    virtual void postServerSpecialize(const ServerSpecializeArgs* args) {}
};

} // namespace zygisk

// Macros for registering a module
#define REGISTER_ZYGISK_MODULE(clazz) \
    extern "C" [[gnu::visibility("default")]] void zygisk_module_entry(zygisk::Api* api, JNIEnv* env) { \
        auto module = new clazz(); \
        module->onLoad(api, env); \
    }

#define REGISTER_ZYGISK_COMPANION(func) \
    extern "C" [[gnu::visibility("default")]] void zygisk_companion_entry(int fd) { \
        func(fd); \
    }
