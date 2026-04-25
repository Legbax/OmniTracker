# OmniTracker — Notas para Claude

OmniTracker es un monitor de identificadores Android basado en **Frida** que
intercepta llamadas sensibles en cuatro capas y emite eventos JSONL en tiempo real.
Su propósito es auditar qué identificadores filtra una app objetivo y verificar
que el spoofer OmniShield (proyecto hermano) está cubriendo todos los vectores.

```
┌─────────────────────┐
│  android_monitor.py │   launcher Python (frida-tools, colorama)
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

## 1. Estructura del repo

| Archivo | Líneas aprox. | Rol |
|---------|---------------|-----|
| `android_monitor.py` | ~590 | Launcher: spawn/attach, multi-layer load, JSONL output, stealth bridge |
| `hooks/layer1_java.js` | ~2770 | Java: IMEI, IMSI, Android ID, Location, Clipboard, Camera, Mic, Sensores, etc. |
| `hooks/layer2_native.js` | ~1260 | libc: open/read/execve/dlopen, `__system_property_get`, ioctl de red, `SENSITIVE_PROPS` (~130 keys) |
| `hooks/layer3_binder.js` | ~1120 | Binder IPC: ITelephony, ISub, ILocationManager, IClipboard, IPhoneSubInfo, IPackageManager |
| `hooks/layer4_scanner.js` | ~900 | Escaneos one-shot: módulos sospechosos, RWX regions, /proc/self/maps, hooks Xposed/inline; detector de coherencia (sección 3b/3c) |
| `patch_frida.py` | ~135 | Renombra strings runtime-visibles del binario `frida-server` (anti-detección Snapchat) |
| `start_stealth.sh` | ~115 | Push del binario stealth + `adb forward 127.0.0.1:8443`, sin abstract socket |
| `extract_all.py` | ~60 | Pull masivo de DBs/SharedPrefs del dispositivo |
| `generate_report.py` | ~260 | Análisis post-mortem de archivos `.jsonl` |
| `bin/frida-server*` | binario | Frida-server upstream + variante stealth (string-patched) |
| `requirements.txt` | — | `frida`, `frida-tools`, `colorama` |
| `README_monitor.md` | — | Guía de instalación/uso para usuarios finales (en español) |
| `captures/` | — | Output dir por defecto para JSONL de capturas |

---

## 2. Capas y tipos de eventos

### Layer 1 — Java framework
`IMEI` · `IMSI` · `PHONE_NUMBER` · `SIM_SERIAL` · `SIM_OPERATOR` · `ANDROID_ID` ·
`MAC_WIFI` · `MAC_BLUETOOTH` · `MAC_NETWORK_IFACE` · `DEVICE_SERIAL` ·
`LOCATION` · `LOCATION_REQUEST` · `CLIPBOARD` · `INSTALLED_APPS` ·
`ACCOUNTS` · `CONTENT_QUERY` · `ADVERTISING_ID` · `SENSOR` · `CAMERA` · `MICROPHONE`

### Layer 2 — Native (libc)
`FILE_OPEN` · `FILE_READ` · `FILE_STAT` · `PROCESS_EXEC` · `IOCTL_NETWORK` ·
`NETWORK_IFACE_ENUM` · `DLOPEN` · `SYSTEM_PROPERTY`

### Layer 3 — Binder IPC
`BINDER_TX_TELEPHONY` · `BINDER_TX_LOCATION` · `BINDER_TX_CLIPBOARD` ·
`BINDER_TX_PACKAGE_MANAGER` · `BINDER_TX_SMS` · `BINDER_TX_WIFI` ·
`BINDER_TX_BLUETOOTH` · `BINDER_TX_ACCOUNTS` · `BINDER_TX_PHONE_SUB_INFO` ·
`BINDER_TX_UNKNOWN`

### Layer 4 — Scanner / detección
- One-shot: `SCANNER_MODULE_SUSPICIOUS`, `SCANNER_XPOSED_HOOK`,
  `SCANNER_METHOD_HOOKED`, `SCANNER_NATIVE_HOOK`, `SCANNER_GOT_TAMPERED`,
  `SCANNER_RWX_REGIONS`, `SCANNER_CLASS_OMNISHIELD`.
- Coherencia (sección 3b/3c, ver §4): `COHERENCE_FINGERPRINT_DIVERGENCE`,
  `COHERENCE_BUILDID_DIVERGENCE`, `COHERENCE_SERIAL_DIVERGENCE`,
  `COHERENCE_FINGERPRINT_INTERNAL_MISMATCH`, `COHERENCE_TELEPHONY_LEAK`,
  `COHERENCE_SECURITY_POSTURE_LEAK`, `COHERENCE_JAVA_NATIVE_DIVERGENCE`.
- Resumen de spoofing: `SPOOF_SUMMARY` (annotated en `format_event`).

---

## 3. Lifecycle del agent

```
android_monitor.py
  ├── connect()
  │     ├── _apply_miui_fix()            # crea theme_compatibility.xml si falta
  │     └── frida.get_device_manager().add_remote_device("127.0.0.1:8443")
  │                                       # routea por adb forward, evita abstract socket
  ├── load_hooks([java, native, binder, scanner])
  │     └── concatena los 4 archivos JS en un solo script
  ├── spawn() | attach()
  ├── on('message', handler)             # recibe eventos `send({...})`
  │     └── format_event(payload)        # imprime con colorama; escribe JSONL si --output
  └── resume()                            # solo en --spawn
```

`globalThis._OT_SCANNER_RAN` en layer4 evita duplicar los escaneos one-shot
si el agent se re-attachea al mismo proceso (script reload o crash recovery).

---

## 4. Cobertura Frida — alineación con OmniShield v1.52.2-sprint1-coherence

OmniTracker es el espejo de OmniShield: cualquier sysprop / tx-code / campo
hookeado en OmniShield debe estar también monitorizado aquí, o el spoof produce
"eventos invisibles" (el valor cambia pero el monitor no lo emite).

**Capas alineadas para v1.52.2 (2026-04-24):**

- **`layer2_native.js` `SENSITIVE_PROPS`** (~130 keys) — cubre las 6 variantes
  de `serialno` (invariant #41), las 7 variantes de `*.build.fingerprint`
  (invariant #42, incluye `ro.bootimage.build.fingerprint` nueva en v1.52),
  las 7 particiones de `*.build.id` (Sprint 2.1 C7), y los pares
  `ro.build.tags` / `ro.build.type` retail (`user`/`release-keys`).
- **`layer3_binder.js`** — tx-codes `ITelephony$Stub` 15/22/23/24/36 +
  `ISub$Stub` 1/3/7/14/15 ya cubren los paths MCC/MNC/operator/simState/
  defaultSubId que consume el `tl_telReplyMode` de invariant #43.
- **`layer4_scanner.js` sección 3b/3c** — detector de coherencia que
  emite los siguientes eventos tras el snapshot de propiedades:
  - `COHERENCE_FINGERPRINT_DIVERGENCE` — >1 valor distinto entre las 7
    variantes de fingerprint (indica cache-drift o hueco en el hook).
  - `COHERENCE_BUILDID_DIVERGENCE` — >1 valor distinto entre las 7
    variantes de `*.build.id`.
  - `COHERENCE_SERIAL_DIVERGENCE` — >1 valor distinto entre las 6 variantes
    de serial.
  - `COHERENCE_FINGERPRINT_INTERNAL_MISMATCH` — parsea el fingerprint en
    `brand/product/device:release/BUILD_ID/INCREMENTAL:TYPE/TAGS` y
    compara con `ro.build.id`, `ro.build.type`, `ro.build.tags` (detecta
    fuga por falta del hook sibling).
  - `COHERENCE_TELEPHONY_LEAK` — `gsm.*operator.numeric` no pertenece a
    `US_CARRIERS` (310260/310410/311480/311580) o `iso-country != us`.
  - `COHERENCE_SECURITY_POSTURE_LEAK` — fuga de `ro.secure/ro.debuggable/
    ro.boot.verifiedbootstate/ro.boot.flash.locked` inconsistente con
    pretensión retail (locked-bootloader + `user/release-keys`).
  - `COHERENCE_JAVA_NATIVE_DIVERGENCE` — compara cada campo `Build.*` Java
    contra su `ro.*` nativo equivalente (14 pares). Divergencia = hueco
    en uno de los dos layers del spoof de OmniShield (JNI `SetStatic*Field`
    vs `my_system_property_get`).

**Cómo agregar cobertura cuando OmniShield añada un sysprop nuevo:**

1. Agregar la key a `SENSITIVE_PROPS` en `layer2_native.js`.
2. Agregar la key a `propsToCheck` en `layer4_scanner.js` (sección 3).
3. Si forma parte de un cluster coherente (p.ej. nueva partición de
   fingerprint), añadirla a `fpVariants` / `bidVariants` / `serVariants`
   en `layer4_scanner.js` sección 3b.
4. Si es un campo `Build.*` Java nuevo, añadir el par a `crossMap` en
   sección 3c.

---

## 5. Modo stealth (anti-detección Snapchat)

`patch_frida.py` reemplaza strings runtime-visibles en el binario
`bin/frida-server`:

| Original | Patcheado |
|----------|-----------|
| `frida-server` (process name) | `.android-helper` |
| `frida-agent-*.so` | `linux-agent-*.so` |
| `gum-js-loop`, `gmain` (thread names) | `lib-js-loop`, `lmain` |
| Abstract socket `@/frida-<uuid>` | `@/linux-<uuid>` |

`start_stealth.sh` lanza la variante stealth en `127.0.0.1:8443` (no
`0.0.0.0:27042`), usa `adb forward` para que el cliente la alcance, y nunca
expone abstract socket reachable desde otras apps. El monitor se conecta
con `--remote 127.0.0.1:8443`.

**Verificación rápida:**
```bash
adb shell "su -c 'cat /proc/net/unix | grep frida'"   # debe estar vacío
adb shell "su -c 'pgrep -af android-helper'"          # debe mostrar PID
```

---

## 6. Uso típico

```bash
# Listar apps
python android_monitor.py --list-apps

# Capturar Snapchat desde el spawn, todas las capas, output a JSONL
python android_monitor.py \
    --remote 127.0.0.1:8443 \
    --package com.snapchat.android \
    --spawn \
    --layers java,native,binder,scanner \
    --output captures/snap_$(date +%Y%m%d_%H%M%S).jsonl

# Análisis post-mortem
python generate_report.py captures/snap_*.jsonl
```

---

## 7. Convenciones del proyecto

- **Comentarios y docs en español** (este `CLAUDE.md`, `README_monitor.md`).
  Los identificadores de código quedan en inglés.
- **PRs en commits**: tag corto al inicio del subject — `fix: …`, `docs: …`.
- **Shell del usuario**: Windows `cmd.exe` para ADB. En este repo, todos los
  comandos `adb` deben usar:
  - Comillas dobles `"` (no simples `'`).
  - Sin `$()`, `|`, `&&` ni sustitución Unix en el host. Si necesitas
    encadenar comandos, usar `adb shell "cmd1 && cmd2"` (todo dentro del
    shell del Android).
  - `grep` no existe en `cmd`; siempre `adb shell "... | grep ..."`.
- **Gists de GitHub**: NO uses `WebFetch` — el dominio
  `gist.githubusercontent.com` no es accesible. Usa:
  ```bash
  curl -sL "https://gist.githubusercontent.com/USER/ID/raw/FILE"
  # o
  gh gist view <ID>
  ```
- **Formato de evento JSONL** (un objeto por línea):
  ```json
  {"layer":"java","type":"IMEI","value":"351...","caller":"com.app.X.method():42",
   "stack":["..."],"ts":1714000000000}
  ```
- **Re-attach**: layer4 detecta `globalThis._OT_SCANNER_RAN` para no repetir
  los escaneos one-shot en re-attach. Si añades un nuevo escaneo one-shot,
  ponerlo bajo el mismo guardia.

---

## 8. Troubleshooting rápido

| Error | Causa / fix |
|-------|-------------|
| `frida.ServerNotRunningError` | Relanzar `./start_stealth.sh restart` |
| `version mismatch` | El paquete `frida` Python y el binario `bin/frida-server` deben coincidir exactamente |
| `Failed to spawn (TimedOut)` | MIUI sin `theme_compatibility.xml` — `_apply_miui_fix()` lo crea, pero verifica que el dispositivo esté rooteado |
| Sin eventos de Binder | Algunos dispositivos usan `/dev/hwbinder`; layer3 detecta ambos |
| App detecta Frida | Verificar que se está usando el binario stealth + puerto 8443, no el upstream |
| `_OT_SCANNER_RAN` ya marcado | Solo se emite `__SKIP__`. Para forzar re-scan, kill app y `--spawn` |

---

## 9. Protocolo de actualización de este archivo

Cuando se modifica el monitor:
1. Añadir entrada al §1 si se crea un archivo nuevo o cambian conteos
   significativamente.
2. Añadir tipo de evento al §2 si se añade uno nuevo.
3. Actualizar §4 cuando OmniShield añada/cambie un sysprop o tx-code y se
   refleja en `layer2_native.js` / `layer3_binder.js` / `layer4_scanner.js`.
4. Actualizar §5 si cambia la lista de strings que `patch_frida.py` reemplaza.
5. Actualizar §7 si se introduce una nueva convención (formato de evento,
   shell, naming, etc.).
