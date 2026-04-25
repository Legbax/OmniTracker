# OmniTracker

Monitor dinámico basado en **Frida** para auditar qué identificadores de Android lee
una aplicación en tiempo real. Diseñado para validar la cobertura del spoofer
[OmniShield](https://github.com/Legbax/OmniShield) — proyecto hermano que enmascara
la identidad del dispositivo a nivel Zygisk.

```
┌─────────────────────┐
│  android_monitor.py │   launcher Python (frida-tools, JSONL output)
└──────────┬──────────┘
           │
   ┌───────┴────────┐
   │  Frida agent   │   se inyecta en la app objetivo
   └───────┬────────┘
           │
  ┌────────┴────────────────────────────────────────┐
  │ hooks/layer1_java.js     → APIs de framework    │
  │ hooks/layer2_native.js   → libc + sysprops      │
  │ hooks/layer3_binder.js   → Binder IPC           │
  │ hooks/layer4_scanner.js  → detección + coherencia│
  └─────────────────────────────────────────────────┘
```

---

## ¿Qué intercepta?

| Capa | Eventos representativos |
|------|-------------------------|
| **Java** | `IMEI`, `IMSI`, `ANDROID_ID`, `LOCATION`, `CLIPBOARD`, `ADVERTISING_ID`, `CAMERA`, `MICROPHONE`, `SUBINFO_*` (per-instance SubscriptionInfo getters), `BUILD_*`, `SENSOR`, `MAC_*` |
| **Native** | `__system_property_get`, `open`/`read`/`stat`, `execve`, `dlopen`, ioctls de red, `SENSITIVE_PROPS` (~130 keys) |
| **Binder IPC** | Transacciones a `ITelephony`, `ISub`, `ILocationManager`, `IClipboard`, `IPhoneSubInfo`, `IPackageManager` |
| **Scanner** | One-shot: módulos sospechosos, RWX regions, hooks Xposed/inline. Coherencia: divergencias fingerprint/build-id/serial entre las 6-7 particiones, leak telefonía, postura de seguridad |

Cada evento se emite como una línea JSONL con `layer`, `type`, `value`, `caller`, `stack` y timestamp — listo para análisis post-mortem.

---

## Quick start

```bash
# 1. Dependencias Python
pip install -r requirements.txt

# 2. Push frida-server al device rooteado (ver README_monitor.md para detalles)
adb push frida-server /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"

# 3. Lanzar y capturar
python android_monitor.py --package com.target.app --spawn --output capture.jsonl
```

Para la guía paso-a-paso con instalación, troubleshooting y ejemplos —
**[README_monitor.md](README_monitor.md)**.

---

## Estructura del repo

| Archivo | Rol |
|---------|-----|
| `android_monitor.py` | Launcher: spawn/attach, multi-layer load, JSONL output, stealth bridge |
| `hooks/layer1_java.js` | Java framework: telephony, location, settings, sensors, crypto, … |
| `hooks/layer2_native.js` | libc + sysprops + ioctls + dlopen |
| `hooks/layer3_binder.js` | Binder IPC parsing (Telephony, Sub, Location, Clipboard, …) |
| `hooks/layer4_scanner.js` | Scanner one-shot + detector de coherencia (fingerprint/build-id/serial divergence) |
| `patch_frida.py` | Renombra strings runtime-visibles del binario `frida-server` (anti-detección) |
| `start_stealth.sh` | Push del binario stealth + `adb forward 127.0.0.1:8443` |
| `extract_all.py` | Pull masivo de DBs/SharedPrefs del dispositivo |
| `generate_report.py` | Análisis post-mortem de archivos `.jsonl` |
| `requirements.txt` | `frida`, `frida-tools`, `colorama` |
| `README_monitor.md` | Guía completa de instalación/uso (español) |
| `CLAUDE.md` | Notas técnicas para asistentes IA |

---

## Relación con OmniShield

OmniShield enmascara la identidad del dispositivo a nivel Zygisk, hookeando ~61 funciones
nativas, ~50 métodos JNI y ~6 PLT entries. OmniTracker corre **encima** del módulo y
verifica que el spoofing es coherente — detecta:

- Valores divergentes entre lecturas Java vs nativas (`COHERENCE_JAVA_NATIVE_DIVERGENCE`)
- Fingerprint inconsistente entre particiones (`COHERENCE_FINGERPRINT_DIVERGENCE`)
- Telephony leaks fuera del rango carriers spoofed (`COHERENCE_TELEPHONY_LEAK`)
- Postura de seguridad incoherente con pretensión retail (`COHERENCE_SECURITY_POSTURE_LEAK`)

Cualquier key hookeada en OmniShield que no aparezca en `layer2_native.js`
(`SENSITIVE_PROPS`, `propsToCheck`) o en los detectores de `layer4_scanner.js` produce
un "evento invisible" — el valor se spoofea pero OmniTracker no lo emite. Mantener
ambas listas alineadas es responsabilidad del desarrollador (ver `CLAUDE.md` §"Cobertura
Frida").

---

## Requisitos

- Dispositivo Android **rooteado** (Magisk o KernelSU) — Frida server requiere root para inyectarse
- Python 3.10+
- `adb` (Android Platform Tools) en el PATH
- Binario `frida-server` con versión idéntica al paquete `frida` Python instalado

---

## Output

Captura típica de un signup de Snapchat:

```
[10:23:44]  JAVA    [IMEI]              351234567890123
                    com.snap.fingerprint.DeviceID.collect():42
[10:23:45]  JAVA    [SUBINFO_ICCID]     8901260123456789012
                    com.snap.identity.SimReader.read():88
[10:23:46]  BINDER  [BINDER_TX_TELEPHONY]  code=199 ITelephony
                    descriptor=com.android.internal.telephony.ITelephony
[10:23:47]  SCAN    [COHERENCE_TELEPHONY_LEAK]  mcc=730 (CL) outside US carriers
```

Cada evento crítico (`IMEI`, `IMSI`, `ANDROID_ID`, etc.) se imprime en rojo y va con un
mini stack-trace para identificar el caller.

---

## Licencia y uso responsable

Herramienta para auditoría defensiva de privacidad y verificación de spoofers de identidad.
Probar **solo** en dispositivos propios y aplicaciones donde tengas derecho a inspeccionar
el comportamiento. No utilizar para evadir términos de servicio de terceros.
