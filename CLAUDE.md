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
  ┌────────┴────────────────────────────────────────────────┐
  │ hooks/layer1_java.js      → APIs de framework            │
  │ hooks/layer2_native.js    → libc + sysprops              │
  │ hooks/layer3_binder.js    → Binder IPC                   │
  │ hooks/layer4_scanner.js   → detección + coherencia       │
  │ hooks/layer5_argos.js     → Argos plaintext (Snap)       │
  │ hooks/layer6_scplugin.js  → libscplugin deobf + sysprops │
  │ hooks/layer7_libclient.js → libclient gRPC + Argos JNI   │
  └─────────────────────────────────────────────────────────┘
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
| `hooks/layer5_argos.js` | ~290 | Snap-only: hookea `Lfd0.getAttestationPayloadProto`, `Liew.mpi.e/f` para volcar el plaintext del proto KQ8 antes/después del seal. **2026-04-29**: incluye intento Stalker scoped sobre libscplugin.so (v1+v3) — fired 0 events, ver inv #49 en `OmniShield/CLAUDE.md`. Eventos con bytes adjuntos persistidos como `argos_blobs/<idx>_<TYPE>_<len>B.bin`. Opt-in: `--layers ...,argos`. |
| `hooks/layer6_scplugin.js` | ~285 | Snap-only: hookea el deobfuscator `fcn.00088ab4` de `libscplugin.so` (output via `x8` = `std::string*`) + `__system_property_get/find` filtrados por caller-in-libscplugin. Mapea los 44 callsites identificados estáticamente. Opt-in via `--layers ...,scplugin`. Espera dlopen de `libscplugin.so` (carga lazy en primer call a `iew.mpi.*`). |
| `hooks/layer7_libclient.js` | ~580 | Snap-only: hookea (a) los 4 JNI exports de Argos en `libclient.so`, (b) los exports `*_native_1submit` que reciben `byte[]` serializados pre-gRPC, (c) catch-all sobre `Java_com_snapchat_client_(network\|messaging\|notifications)_*`. Escanea byte[] por substrings de identifiers conocidos (real + spoofed) — un hit en valor SPOOFED = evidencia directa de que el spoof llega al wire. Opt-in via `--layers ...,libclient`. Cap: 200 eventos / 16 blobs por sesión. **AEAD dispatch hook DISABLED** desde 2026-04-29 tras falsificación de `0xbb6220` (ver header del archivo + invariante #46 en OmniShield/CLAUDE.md). |
| `hooks/probe_modules.js` | ~30 | Probe one-shot: enumera módulos cargados filtrados por nombres relevantes (snap/scplugin/kameleon/ferrite/client/crypto/ssl/...). Diagnóstico para verificar qué libs están en memoria durante un signup. Opt-in via `--layers ...,probe`. |
| `hooks/probe_evp_aead.js` | ~120 | Probe Snap-only: hookea `EVP_AEAD_CTX_seal` en TODAS las instancias de `libcrypto.so` (system + ART apex + conscrypt apex). Captura ctx (key 32B), nonce, plaintext head, ciphertext head, lengths. **Resultado falsificación 2026-04-29**: 0 calls durante seal de `iew.mpi.e` — la cifra NO usa libcrypto exports. Probe queda como anti-regresión. Opt-in via `--layers ...,evp_aead`. |
| `hooks/probe_crypto_wide.js` | ~210 | Probe Snap-only: amplía cobertura del anterior a 19 funciones BoringSSL (`EVP_Encrypt*`, `EVP_Cipher*`, `AES_*`, `CRYPTO_chacha_20`, `CRYPTO_gcm128_encrypt`, `HMAC_*`, `ECDSA_*`, `EVP_PKEY_sign`, `RAND_bytes`) + escaneo de exports de `libsigx.so`. **Resultado**: 0 calls durante seal — confirma que NINGUNA API estándar libcrypto es invocada. Opt-in via `--layers ...,crypto_wide`. |
| `hooks/probe_libcamplat_aes.js` | ~250 | Probe Snap-only: hookea `libcamplat+ + 0x793f80` (AES encrypt entry, 76 AESE Mike Hamburg impl), `+0x793820` (AES key setup), `+0x8b1dd8` (init helper). Lazy-load aware (poll + dlopen observer). **Resultado falsificación 2026-04-29**: lib `libcamplat+` NO carga durante signup — su AES es para camera/media platform, no Argos (invariante #47). Opt-in via `--layers ...,camplat_aes`. |
| `hooks/probe_libclient_aes.js` | ~210 | Probe Snap-only: hookea `libclient.so + 0xb3c620` (AES encrypt entry), `+0xc8f590` (GHASH), `+0xb3e4e4` (seal wrapper, 912B EVP_AEAD-style). Captura key schedule, nonce, plaintext, AD, ciphertext. LR histogram dump a 90s. **Resultado 2026-04-29**: AES dispara ANTES del seal (TLS outbound RPC body, no `iew.mpi.e`) — invariante #48. El cipher de `iew.mpi.e` está en libclient.so internal en otro offset no pineado. Opt-in via `--layers ...,libclient_aes`. |
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
`ACCOUNTS` · `CONTENT_QUERY` · `ADVERTISING_ID` · `SENSOR` · `CAMERA` · `MICROPHONE` ·
`SSL_BYPASS` · `OKHTTP_CALL` · `OKHTTP_REQUEST` · `OKHTTP_RESPONSE` ·
`CRONET_REQUEST` · `HTTPURL_CONNECT` · `INTEGRITY_REQUEST`

### Layer 2 — Native (libc + ART)
`FILE_OPEN` · `FILE_READ` · `FILE_STAT` · `PROCESS_EXEC` · `IOCTL_NETWORK` ·
`NETWORK_IFACE_ENUM` · `DLOPEN` · `SYSTEM_PROPERTY` · `PROC_FORK` ·
`PROC_VFORK` · `PROC_CLONE` · `PROC_SPAWN` · `SYSCALL_DIRECT` · `JNI_REGISTER_NATIVES`

### Layer 3 — Binder IPC
`BINDER_TX_TELEPHONY` · `BINDER_TX_LOCATION` · `BINDER_TX_CLIPBOARD` ·
`BINDER_TX_PACKAGE_MANAGER` · `BINDER_TX_SMS` · `BINDER_TX_WIFI` ·
`BINDER_TX_BLUETOOTH` · `BINDER_TX_ACCOUNTS` · `BINDER_TX_PHONE_SUB_INFO` ·
`BINDER_TX_UNKNOWN` · `AIBINDER_TRANSACT`

### Layer 4 — Scanner / detección
- One-shot: `SCANNER_MODULE_SUSPICIOUS`, `SCANNER_XPOSED_HOOK`,
  `SCANNER_METHOD_HOOKED`, `SCANNER_NATIVE_HOOK`, `SCANNER_GOT_TAMPERED`,
  `SCANNER_RWX_REGIONS`, `SCANNER_CLASS_OMNISHIELD`.
- Coherencia (sección 3b/3c, ver §4): `COHERENCE_FINGERPRINT_DIVERGENCE`,
  `COHERENCE_BUILDID_DIVERGENCE`, `COHERENCE_SERIAL_DIVERGENCE`,
  `COHERENCE_FINGERPRINT_INTERNAL_MISMATCH`, `COHERENCE_TELEPHONY_LEAK`,
  `COHERENCE_TELEPHONY_OK` (v1.53+ Chile Simplify y otras personas locales coherentes),
  `COHERENCE_TELEPHONY_UNKNOWN` (país no en CARRIERS_BY_COUNTRY pero SIM/net/iso coherentes entre sí),
  `COHERENCE_SECURITY_POSTURE_LEAK`, `COHERENCE_JAVA_NATIVE_DIVERGENCE`.
- Resumen de spoofing: `SPOOF_SUMMARY` (annotated en `format_event`).

### Layer 5 — Argos plaintext (Snap-only, opt-in)
`ARGOS_PAYLOAD_PROTO` · `ARGOS_PLAINTEXT` · `ARGOS_CIPHERTEXT` ·
`ARGOS_SIGN_INPUT` · `ARGOS_SIGNATURE`

### Layer 6 — libscplugin deep capture (Snap-only, opt-in)
`SCPLUGIN_DEOBF_STR` · `SCPLUGIN_SYSPROP_GET` · `SCPLUGIN_SYSPROP_FIND`

### Layer 7 — libclient.so JNI observation (Snap-only, opt-in)
`LIBCLIENT_ARGOS_CALL` · `LIBCLIENT_GRPC_SUBMIT` · `LIBCLIENT_KNOWN_ID_HIT`

`LIBCLIENT_KNOWN_ID_HIT` es el evento clave: dispara cuando un substring de
la lista `KNOWN_IDS` (IDs reales del SIM físico + IDs spoofed por master_seed
actual) aparece en el body protobuf de un `*_native_1submit` o en un jstring
arg de cualquier export filtrado. Hit en valor SPOOFED = evidencia directa
de que el spoof llega al wire de Snap. Hit en valor REAL = regresión de
OmniShield. `LIBCLIENT_GRPC_SUBMIT` adjunta el body como blob persistido en
`argos_blobs/<idx>_libclient_grpc_submit_<len>B.bin`. Cap: 200 eventos / 16
blobs por sesión. Actualizar `KNOWN_IDS` en `layer7_libclient.js` cuando
rote `master_seed`.

`ARGOS_PLAINTEXT` es el evento clave: bytes del proto KQ8 que entran a
`Liew.mpi.e([B)[B` antes de cifrarse. Cap de 64 emisiones por sesión.
Cada blob se guarda como `argos_blobs/<idx>_<type>_<len>B.bin` junto al JSONL;
el record JSON incluye el campo `blob_file` apuntando al archivo. Cuando el
APK de Snap actualice, los nombres ofuscados (`fd0`, `iew.mpi`) probablemente
roten — verificar contra el bytecode dump más reciente y ajustar `Java.use(...)`.

### Eventos nuevos (2026-04-25, expansión cobertura)

| Evento | Capa | Disparador | Por qué importa |
|---|---|---|---|
| `AIBINDER_TRANSACT` | binder | `libbinder_ndk.AIBinder_transact` | GMS/Play Integrity/ARGOS/Cronet usan NDK binder, no el ioctl tradicional |
| `SYSCALL_DIRECT` | native | `libc.syscall(2)` con NR en lista (ioctl/openat/connect/recvmsg/getrandom/ptrace/prctl/getuid/getpid/gettid/sethostname) | Vendor SDKs (libsigx, libferrite) emiten SVC directo bypaseando los wrappers |
| `JNI_REGISTER_NATIVES` | native | `art::JNI::RegisterNatives` (live) | Inventario de cada método native registrado por las libs de Snap |
| `JNI_REGISTER_NATIVES_RETRO` | native | Retro-walk t+5s vía `Java.enumerateLoadedClassesSync` | Captura clases con métodos native cuyo `RegisterNatives` se ejecutó antes del attach |
| `PROC_SPAWN` | native | `libc.posix_spawn[p]` | Captura el path del ejecutable que `fork`/`vfork`/`clone` no exponen |
| `OKHTTP_REQUEST` | java | `okhttp3.internal.http.RealInterceptorChain.proceed` | Body + headers ANTES del TLS — captura `X-Snapchat-Argos-Token` |
| `CRONET_REQUEST` | java | `org.chromium.net.UrlRequest.start` | Snap usa Cronet para gRPC; OkHttp no lo cubre |
| `HTTPURL_CONNECT` | java | `HttpURLConnection.connect` / `HttpsURLConnection.connect` | Fallback para libs que bypassen OkHttp/Cronet |
| `INTEGRITY_REQUEST` | java | `IntegrityManager.requestIntegrityToken` (+ SafetyNet) | Detectar invocación de Play Integrity (cómputo en GMS, fuera de scope) |

---

## 3. Lifecycle del agent

```
android_monitor.py
  ├── connect()
  │     ├── _apply_miui_fix()            # crea theme_compatibility.xml si falta
  │     └── frida.get_device_manager().add_remote_device("127.0.0.1:8443")
  │                                       # routea por adb forward, evita abstract socket
  ├── load_hooks([java, native, binder, scanner, argos?, scplugin?, libclient?])
  │     └── concatena los archivos JS seleccionados en un solo script
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

### 5.1 Capa kernel: SusFS (KernelSU)

`start_stealth.sh` aplica reglas `ksu_susfs` automáticamente cuando detecta
KernelSU+susfs en el device (controlable vía `OMNI_USE_SUSFS=0` para
desactivar). Las reglas son:

| `ksu_susfs` cmd | Qué oculta |
|---|---|
| `add_sus_path /data/local/tmp/.android-helper` | El binario stealth no aparece en `readdir`/`stat`/`open` para uid≥10000 umounted |
| `add_sus_path_loop ...` | Re-aplica la regla en cada spawn de zygote (Snap arranca DESPUÉS de la setup) |
| `add_sus_kstat ...` | `File.exists()` Java devuelve `false` |
| `add_sus_path /data/local/tmp/.helper.log` | El log del helper también oculto |
| `hide_sus_mnts_for_non_su_procs 1` | `/proc/self/mounts/mountinfo` no leak KSU/zygisk mounts |

Esto complementa al string-patching de `patch_frida.py`: aunque Snap
escanee filesystem o `/proc`, el kernel devuelve "no existe" para los
artefactos de Frida. Detecciones que cubre que `patch_frida.py` no podía:

- `File.exists("/data/local/tmp/.android-helper")` → false
- `Runtime.exec("ls /data/local/tmp")` → no muestra el helper
- `/proc/self/mountinfo` → no leak de zygisk/ksu mount points

Verificar features kernel: `bash ./start_stealth.sh status` (sección final).
Salida esperada en `merlinx`: `v2.1.0` con `CONFIG_KSU_SUSFS_SUS_PATH`,
`CONFIG_KSU_SUSFS_SUS_KSTAT`, `CONFIG_KSU_SUSFS_SUS_MOUNT` enabled.

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
