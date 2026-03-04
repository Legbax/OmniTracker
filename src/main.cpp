#include <android/log.h>
#include <jni.h>
#include <string.h>
#include <memory>
#include "zygisk.hpp"

// Forward declarations of our hook initialization functions
void initNativeHooks(zygisk::Api* api);
void initBinderHooks(zygisk::Api* api);
void initJavaHooks(JNIEnv* env, zygisk::Api* api);

#define LOG_TAG "ZygiskTelemetrySniffer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

class TelemetrySnifferModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api_ = api;
        this->env_ = env;
        LOGI("Telemetry Sniffer Module loaded in Zygote.");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        // Here we can decide whether to inject into the application.
        // For a telemetry sniffer, we want to inject into specific apps or all user apps.
        // We'll proceed with all apps for this example.

        if (args->nice_name == nullptr) {
            LOGW("preAppSpecialize: nice_name is null.");
            return;
        }

        LOGI("App specializing: %s", args->nice_name);

        // Initialize Native (C/C++) Hooks
        initNativeHooks(api_);

        // Initialize Binder Hooks
        initBinderHooks(api_);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        // Here, the process is already specialized as the application.
        // We can now safely set up Java-level hooks via JNI.

        if (args->nice_name == nullptr) {
            return;
        }

        LOGI("Post App specializing: %s. Setting up Java hooks.", args->nice_name);
        initJavaHooks(env_, api_);
    }

private:
    zygisk::Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
};

// Register our module with Zygisk
REGISTER_ZYGISK_MODULE(TelemetrySnifferModule)
