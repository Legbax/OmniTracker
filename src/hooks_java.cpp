#include <android/log.h>
#include <jni.h>
#include "zygisk.hpp"
#include "hooks.h"

#define LOG_TAG "ZygiskTelemetrySnifferJava"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#include <dlfcn.h>

// Original functions for SystemProperties
static jstring (*old_native_get)(JNIEnv* env, jclass clazz, jstring key, jstring def) = nullptr;

// Hooked SystemProperties.native_get
jstring my_native_get(JNIEnv* env, jclass clazz, jstring key, jstring def) {
    if (key != nullptr) {
        const char* keyChars = env->GetStringUTFChars(key, nullptr);
        LOGI("android.os.SystemProperties.get() intercepted for key: %s", keyChars);
        env->ReleaseStringUTFChars(key, keyChars);
    }

    // If we failed to get the original pointer, we can try to find it or fallback
    if (old_native_get != nullptr) {
        return old_native_get(env, clazz, key, def);
    } else {
        // Fallback or empty string if we can't call original
        LOGE("old_native_get is null, returning default");
        return def;
    }
}

// Original function for Settings.Secure.getStringForUser
static jstring (*old_settings_get_string)(JNIEnv* env, jclass clazz, jobject resolver, jstring name, jint userHandle) = nullptr;

// Hooked Settings.Secure.getStringForUser
jstring my_settings_get_string(JNIEnv* env, jclass clazz, jobject resolver, jstring name, jint userHandle) {
    if (name != nullptr) {
        const char* nameChars = env->GetStringUTFChars(name, nullptr);
        LOGI("android.provider.Settings.Secure.getStringForUser() intercepted for name: %s", nameChars);
        env->ReleaseStringUTFChars(name, nameChars);
    }

    if (old_settings_get_string != nullptr) {
        return old_settings_get_string(env, clazz, resolver, name, userHandle);
    } else {
        LOGE("old_settings_get_string is null");
        return nullptr;
    }
}

void initJavaHooks(JNIEnv* env, zygisk::Api* api) {
    if (env == nullptr) return;

    // We can use Zygisk's pltHookRegister to hook the native JNI implementations directly if they are exported or accessible.
    // For android.os.SystemProperties, the native implementation is typically in libandroid_runtime.so

    void* handle = dlopen("libandroid_runtime.so", RTLD_NOW);
    if (handle) {
        // Find the actual native function for SystemProperties.native_get
        // The symbol name might vary, this is an example (SystemProperties_getString in android_os_SystemProperties.cpp)
        // A more robust implementation would use a proper symbol resolver or PLT hooking on the library itself.
        void* sym_native_get = dlsym(handle, "_ZN7android14SystemProperties9GetStringEPKc"); // Example symbol
        if (sym_native_get) {
            old_native_get = (jstring (*)(JNIEnv*, jclass, jstring, jstring))sym_native_get;
            api->pltHookRegister("libandroid_runtime.so", "_ZN7android14SystemProperties9GetStringEPKc", (void*)my_native_get, (void**)&old_native_get);
            LOGI("Found and hooked SystemProperties native function via PLT");
        } else {
            LOGW("Could not find SystemProperties native symbol");
        }

        dlclose(handle);
    }

    // Alternatively, if we just want to replace methods and rely on the fact that we can't easily get the original via hookJniNativeMethods
    // without a trampoline, we can log and return default if we don't have the original.

    jclass systemPropertiesClass = env->FindClass("android/os/SystemProperties");
    if (systemPropertiesClass != nullptr && old_native_get == nullptr) {
         // We might decide not to use hookJniNativeMethods if we can't get the original, to avoid crashing.
         // For a complete solution, dex injection via companion is the safest way to hook Java methods.
         LOGW("JNI hooking for SystemProperties skipped via hookJniNativeMethods because old pointer cannot be safely retrieved without external framework");
    }

    jclass settingsSecureClass = env->FindClass("android/provider/Settings$Secure");
    if (settingsSecureClass != nullptr && old_settings_get_string == nullptr) {
        LOGW("JNI hooking for Settings.Secure skipped because old pointer cannot be safely retrieved without external framework");
    }

    api->pltHookCommit();
}
