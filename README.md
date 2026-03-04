# Zygisk Telemetry Sniffer

This module is an independent "Sniffer de Telemetría" that operates within the Zygisk environment (Magisk / KernelSU) to monitor Android application tracking behaviors without leaving an observable trace in userland environments.

## Architecture

The module intercepts tracking and telemetry API calls across the three primary layers of Android:

### 1. Framework Layer (Java)
Intercepts calls to `android.os.SystemProperties` and `android.provider.Settings` via JNI registration hooking. This unveils which high-level APIs an application uses to query device models, brands, or advertising identifiers.

### 2. Native Library Layer (C/C++)
Executes inline PLT hooks on libc functions such as `open`, `read`, `stat`, `execve`, and `__system_property_get`. This is critical for catching apps that attempt to bypass Java hooks by reading directly from locations like `/proc` or `/dev/__properties__`.

### 3. Communication Layer (Binder)
Monitors `ioctl` transactions towards `/dev/binder`. Nearly all sensitive information (IMEI, location, network status) passes through Binder. Seeing the traffic of these data parcels allows understanding of what an application queries from the system, even when it uses complex native methodologies.

## Advantages

- **Aislamiento de Depuración:** Records all access to files and properties into an external log, so primary protection modules do not interfere with the hooks.
- **Identificación de Falsos Positivos:** Reveals unexpected file reads, such as security certificates, package lists (visibility blocking), or system mount signatures.
- **Mapeo de Transaction Codes (Binder):** Allows exact mapping of which transaction code corresponds to hardware ID queries on a specific Android version.

## Usage

1. **Compilation:** Build the shared library (`.so`) using Android NDK and CMake.
2. **Deployment:** Create a zip containing the `.so`, `module.prop`, and `customize.sh` and flash it via Magisk or KernelSU.
3. **Capture:** Run the target application.
4. **Analysis:** Review `logcat` logs filtered by `ZygiskTelemetrySniffer` to search for data leaks.
5. **Implementation:** Use the identified query paths/mechanisms to implement precise anti-tracking countermeasures.

```bash
# Example logcat command to view logs
adb logcat -s ZygiskTelemetrySniffer:I ZygiskTelemetrySnifferNative:I ZygiskTelemetrySnifferBinder:I ZygiskTelemetrySnifferJava:I
```
