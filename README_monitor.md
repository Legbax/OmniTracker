# Android 3-Layer Identifier Monitor

Herramienta de análisis dinámico basada en **Frida** que intercepta en tiempo real
todas las llamadas a APIs sensibles de Android en tres capas:

| Capa | Qué intercepta |
|------|----------------|
| **Java** | Android framework APIs: IMEI, IMSI, Android ID, GPS, Clipboard, Cámara, Micrófono, Contactos, Cuentas, Advertising ID, etc. |
| **Native** | Syscalls de libc: `open`, `read`, `execve`, `dlopen`, `__system_property_get`, ioctls de red, etc. |
| **Binder IPC** | Transacciones al kernel Binder: Telephony, Location, SMS, PackageManager, Bluetooth, WiFi, etc. |

---

## Archivos a descargar

### 1. Python 3.10 o superior
Si no lo tienes instalado: **https://www.python.org/downloads/**

### 2. Android Platform Tools (ADB)
Necesario para comunicarse con el dispositivo:
**https://developer.android.com/tools/releases/platform-tools**

Descomprime y agrega la carpeta al PATH, o úsala desde donde la descargaste.

### 3. frida-server (binario nativo para Android)

> **CRÍTICO:** La versión del binario debe coincidir **exactamente** con la versión
> del paquete Python `frida` que instales.

**URL de releases:** https://github.com/frida/frida/releases

Primero instala frida en Python para conocer qué versión necesitas:
```bash
pip install frida frida-tools colorama
python -m pip show frida   # Anota el número de versión
```

Luego en la página de releases, busca esa versión y bajo "Assets" descarga:

| CPU del dispositivo | Archivo a descargar |
|---------------------|---------------------|
| ARM 64-bit (mayoría de dispositivos 2017+) | `frida-server-X.X.X-android-arm64.xz` |
| ARM 32-bit (dispositivos antiguos) | `frida-server-X.X.X-android-arm.xz` |
| x86_64 (emuladores AVD de Android Studio) | `frida-server-X.X.X-android-x86_64.xz` |

Para verificar la arquitectura de tu dispositivo:
```bash
adb shell getprop ro.product.cpu.abi
# arm64-v8a  → descarga arm64
# armeabi-v7a → descarga arm
```

Descomprime el `.xz` (con 7-Zip, WinRAR, `xz -d` en Linux/Mac) y renombra el binario a `frida-server`.

---

## Setup paso a paso

### Paso 1 — Habilitar USB Debugging

1. `Ajustes` → `Acerca del teléfono`
2. Toca **7 veces** en `Número de compilación` (activa las opciones de desarrollador)
3. `Ajustes` → `Opciones de desarrollador` → activar **Depuración USB**
4. Conecta el cable USB a tu PC
5. En el teléfono: acepta el popup "Permitir depuración USB desde este equipo"
6. Verifica la conexión:
   ```bash
   adb devices
   # Debe mostrar tu dispositivo con estado "device" (no "unauthorized")
   ```

> **Requisito:** el dispositivo debe estar **rooteado** con Magisk o KernelSU.
> Sin root, `frida-server` no puede inyectarse en otros procesos.

### Paso 2 — Instalar frida-server en el dispositivo

```bash
# Copia el binario
adb push frida-server /data/local/tmp/

# Da permisos de ejecución
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"

# Inícialo en segundo plano
adb shell "su -c '/data/local/tmp/frida-server &'"

# Verifica que está corriendo
adb shell "su -c 'ps | grep frida'"
```

> Repite el último comando cada vez que reinicies el teléfono.

### Paso 3 — Instalar dependencias Python

```bash
pip install -r requirements.txt
```

### Paso 4 — Verificar la conexión

```bash
python android_monitor.py --list-apps
```

Debe mostrar la lista de aplicaciones instaladas en el dispositivo.

---

## Uso

### Comandos principales

```bash
# Listar apps instaladas / en ejecución
python android_monitor.py --list-apps

# Monitorear una app desde el inicio (RECOMENDADO — captura todo desde arranque)
python android_monitor.py --package com.ejemplo.app --spawn

# Adjuntarse a una app que ya está corriendo
python android_monitor.py --package com.ejemplo.app --attach

# Guardar todos los eventos en archivo para análisis posterior
python android_monitor.py --package com.ejemplo.app --spawn --output reporte.jsonl

# Monitorear solo capas específicas (reduce el ruido)
python android_monitor.py --package com.ejemplo.app --spawn --layers java,binder

# Monitorear todas las capas con log
python android_monitor.py --package com.ejemplo.app --spawn \
    --layers java,native,binder --output reporte.jsonl
```

### Referencia de argumentos

| Argumento | Descripción |
|-----------|-------------|
| `--package PKG` | Nombre del paquete Android (ej: `com.whatsapp`) |
| `--spawn` | Inicia la app desde cero e inyecta hooks al inicio *(por defecto)* |
| `--attach` | Se adjunta a un proceso ya en ejecución |
| `--layers` | Capas separadas por coma: `java`, `native`, `binder` *(por defecto: todas)* |
| `--output FILE` | Archivo de log en formato JSON Lines (`.jsonl`) |
| `--list-apps` | Lista apps del dispositivo y sale |

---

## Interpretación de la salida

```
[10:23:44]  JAVA    [IMEI]              351234567890123
                    com.bad.app.DeviceInfo.collect():42
                      com.bad.app.MainActivity.onCreate():15

[10:23:45]  JAVA    [ANDROID_ID]        a1b2c3d4e5f6a1b2
                    com.bad.app.analytics.Session.init():88

[10:23:46]  NATIVE  [SYSTEM_PROPERTY]   ro.serialno = ABC123XYZ
                    libtracker.so!0x3a4f20

[10:23:47]  BINDER  [BINDER_TX_TELEPHONY]  getDeviceId
                    handle=3 interface=android.telephony.ITelephony
```

### Colores

| Color | Capa |
|-------|------|
| **Rojo** (cualquier capa) | Dato crítico: IMEI, IMSI, ubicación, micrófono, cámara, cuentas, SIM |
| Cyan | Java framework |
| Amarillo | Native (C/C++) |
| Magenta | Binder IPC |

### Tipos de eventos por capa

**Java:**
`IMEI` · `IMSI` · `PHONE_NUMBER` · `SIM_SERIAL` · `SIM_OPERATOR` · `ANDROID_ID` ·
`MAC_WIFI` · `MAC_BLUETOOTH` · `MAC_NETWORK_IFACE` · `DEVICE_SERIAL` ·
`LOCATION` · `LOCATION_REQUEST` · `CLIPBOARD` · `INSTALLED_APPS` ·
`ACCOUNTS` · `CONTENT_QUERY` · `ADVERTISING_ID` · `SENSOR` · `CAMERA` · `MICROPHONE`

**Native:**
`FILE_OPEN` · `FILE_READ` · `FILE_STAT` · `PROCESS_EXEC` · `IOCTL_NETWORK` ·
`NETWORK_IFACE_ENUM` · `DLOPEN` · `SYSTEM_PROPERTY`

**Binder:**
`BINDER_TX_TELEPHONY` · `BINDER_TX_LOCATION` · `BINDER_TX_CLIPBOARD` ·
`BINDER_TX_PACKAGE_MANAGER` · `BINDER_TX_SMS` · `BINDER_TX_WIFI` ·
`BINDER_TX_BLUETOOTH` · `BINDER_TX_ACCOUNTS` · `BINDER_TX_PHONE_SUB_INFO` ·
`BINDER_TX_UNKNOWN`

---

## Análisis del archivo `.jsonl`

Cada línea del archivo de salida es un objeto JSON independiente:

```json
{
  "layer": "java",
  "type": "IMEI",
  "value": "351234567890123",
  "caller": "com.bad.app.DeviceInfo.collect():42",
  "stack": ["com.bad.app.DeviceInfo.collect():42", "com.bad.app.MainActivity.onCreate():15"],
  "timestamp": "2026-03-24T10:23:44.123456"
}
```

### Script de análisis rápido

```python
import json
from collections import Counter

with open("reporte.jsonl") as f:
    events = [json.loads(line) for line in f if line.strip()]

# Resumen por tipo
tipos = Counter(e["type"] for e in events)
print("=== Eventos por tipo ===")
for tipo, count in tipos.most_common():
    print(f"  {count:4d}  {tipo}")

# Solo eventos críticos
CRITICOS = {"IMEI","IMSI","PHONE_NUMBER","SIM_SERIAL","ANDROID_ID",
            "ADVERTISING_ID","LOCATION","MICROPHONE","CAMERA","ACCOUNTS"}
print("\n=== Datos CRÍTICOS accedidos ===")
for e in events:
    if e["type"] in CRITICOS:
        print(f"  [{e['type']}] {e['value']}  ←  {e.get('caller','?')}")
```

---

## Solución de problemas

| Error | Solución |
|-------|----------|
| `No USB device found` | Verifica USB Debugging, acepta el popup en el teléfono, reinstala ADB drivers |
| `frida.ProcessNotFoundError` | El paquete no existe o está mal escrito. Usa `--list-apps` para confirmarlo |
| `Failed to spawn` | frida-server no está corriendo. Repite el Paso 2 |
| `version mismatch` | La versión de `frida` Python y `frida-server` deben ser idénticas |
| Sin output de Binder | Algunos dispositivos usan `/dev/hwbinder`. El layer 3 detecta ambos |
| App crashea al spawn | Usa `--attach` después de abrir la app manualmente |

---

## Estructura del proyecto

```
OmniTracker/
├── android_monitor.py      ← Launcher principal
├── requirements.txt        ← Dependencias Python
├── README.md               ← Esta guía
└── hooks/
    ├── layer1_java.js      ← Hooks de Java framework
    ├── layer2_native.js    ← Hooks de funciones nativas
    └── layer3_binder.js    ← Hooks de transacciones Binder
```
