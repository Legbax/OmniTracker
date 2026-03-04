#pragma once

#include "zygisk.hpp"
#include <jni.h>

// Initialize Native Hooks
void initNativeHooks(zygisk::Api* api);

// Initialize Binder Hooks
void initBinderHooks(zygisk::Api* api);

// Initialize Java Hooks
void initJavaHooks(JNIEnv* env, zygisk::Api* api);
