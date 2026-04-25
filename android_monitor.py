#!/usr/bin/env python3
"""
android_monitor.py -- Android 3-Layer Identifier Monitor (Frida-based)

Intercepts sensitive API calls across three layers:
  Layer 1 (Java)   -- Android framework: IMEI, IMSI, Android ID, Location, etc.
  Layer 2 (Native) -- libc syscalls: open/read/execve/property_get/dlopen/etc.
  Layer 3 (Binder) -- IPC transactions: Telephony, Location, Clipboard, SMS, etc.

Requirements:
  pip install frida frida-tools colorama
  frida-server running on rooted Android device (same version as frida package)

Usage:
  python android_monitor.py --list-apps
  python android_monitor.py --package com.example.app --spawn
  python android_monitor.py --package com.example.app --attach --output report.jsonl
  python android_monitor.py --package com.example.app --spawn --layers java,binder
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import frida
except ImportError:
    print("[!] frida not installed. Run: pip install frida frida-tools")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

# --- Color helpers ------------------------------------------------------------

LAYER_COLORS = {
    "java":    Fore.CYAN    if HAS_COLOR else "",
    "native":  Fore.YELLOW  if HAS_COLOR else "",
    "binder":  Fore.MAGENTA if HAS_COLOR else "",
    "scanner": Fore.GREEN   if HAS_COLOR else "",
}

ALERT_TYPES = {
    "IMEI", "IMSI", "PHONE_NUMBER", "SIM_SERIAL",
    "ANDROID_ID", "ADVERTISING_ID", "DEVICE_SERIAL",
    "LOCATION", "LOCATION_REQUEST",
    "MICROPHONE", "CAMERA",
    "ACCOUNTS", "CONTACTS", "CONTENT_QUERY",
    "BINDER_TX_TELEPHONY", "BINDER_TX_LOCATION",
    "BINDER_TX_PHONE_SUB_INFO", "BINDER_TX_SMS",
    "CLIPBOARD",
    # Scanner alerts
    "SCANNER_MODULE_SUSPICIOUS", "SCANNER_XPOSED_HOOK",
    "SCANNER_METHOD_HOOKED", "SCANNER_NATIVE_HOOK",
    "SCANNER_GOT_TAMPERED", "SCANNER_RWX_REGIONS",
    "SCANNER_CLASS_OMNISHIELD",
    # Spoof detection
    "SPOOF_SUMMARY",
}

RESET = Style.RESET_ALL if HAS_COLOR else ""
RED   = Fore.RED        if HAS_COLOR else ""
BOLD  = Style.BRIGHT    if HAS_COLOR else ""
DIM   = Style.DIM       if HAS_COLOR else ""


def colorize(text, color):
    return f"{color}{text}{RESET}" if HAS_COLOR else text


# --- Hook script loader -------------------------------------------------------

HOOKS_DIR = Path(__file__).parent / "hooks"

LAYER_FILES = {
    "java":    HOOKS_DIR / "layer1_java.js",
    "native":  HOOKS_DIR / "layer2_native.js",
    "binder":  HOOKS_DIR / "layer3_binder.js",
    "scanner": HOOKS_DIR / "layer4_scanner.js",
}


def load_hooks(layers: list[str]) -> str:
    parts = []
    for layer in layers:
        path = LAYER_FILES.get(layer)
        if not path or not path.exists():
            print(f"[!] Hook file not found: {path}")
            continue
        parts.append(path.read_text(encoding="utf-8"))
    return "\n\n".join(parts)


# --- Output formatting --------------------------------------------------------

def format_event(event: dict) -> str:
    layer = event.get("layer", "?")
    etype = event.get("type", "?")
    value = event.get("value") or ""
    caller = event.get("caller") or event.get("property") or ""
    ts = datetime.now().strftime("%H:%M:%S")

    layer_color = LAYER_COLORS.get(layer, "")
    is_alert = etype in ALERT_TYPES

    type_str = f"[{etype}]"
    if is_alert:
        type_str = colorize(type_str, RED + BOLD)
    else:
        type_str = colorize(type_str, layer_color)

    layer_tag = colorize(f"* {layer.upper():<6}", layer_color + BOLD)

    # Truncate long values
    display_value = value[:120] + ("..." if len(value) > 120 else "")

    line = f"[{ts}] {layer_tag} {type_str:<30} {display_value}"
    if caller:
        line += f"\n           {colorize(caller, DIM)}"

    # Show abbreviated stack if available
    stack = event.get("stack") or event.get("backtrace") or []
    if stack and len(stack) > 1:
        for frame in stack[1:4]:
            line += f"\n             {colorize(str(frame), DIM)}"

    # Anomaly annotations (spoof detection)
    anomaly = event.get("anomaly")
    if anomaly:
        reason = event.get("anomalyReason", "")
        sp_val = event.get("syspropValue", "")
        anom_text = f"ANOMALY: {anomaly}"
        if reason:
            anom_text += f" -- {reason}"
        if sp_val:
            anom_text += f" [sysprop: {sp_val}]"
        line += f"\n           {colorize(anom_text, RED + BOLD)}"

    # SPOOF_SUMMARY formatting
    if etype == "SPOOF_SUMMARY":
        for a in event.get("anomalies", []):
            field = a.get("field", "?")
            issue = a.get("issue", "")
            java_val = a.get("javaValue", "")
            sp_val = a.get("syspropValue", "")
            detail = f"  {field}: {issue}"
            if java_val or sp_val:
                detail += f" (java='{java_val}', sysprop='{sp_val}')"
            line += f"\n           {colorize(detail, RED)}"

    return line


# --- Frida session manager ----------------------------------------------------

class AndroidMonitor:
    def __init__(self, args):
        self.args = args
        self.device = None
        self.session = None
        self.scripts: list = []
        self.log_file = None
        self.event_count = 0

    # -- Device connection --

    def _adb(self, *args, timeout=8) -> str:
        """Run an adb command and return stdout."""
        import subprocess
        result = subprocess.run(["adb", "shell", *args],
                                capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()

    def _apply_miui_fix(self):
        """MIUI workaround: ensure theme_compatibility.xml exists (prevents Frida helper crash)."""
        self._adb("su", "-c",
                  "mkdir -p /data/system/theme_config; "
                  "[ -s /data/system/theme_config/theme_compatibility.xml ] || "
                  "cp /system/media/theme/theme_compatibility.xml "
                  "/data/system/theme_config/theme_compatibility.xml 2>/dev/null")

    def connect(self) -> bool:
        self._apply_miui_fix()
        # --remote H:P routes through the stealth (string-patched) frida-server
        # over `adb forward`, so the abstract socket prefix never reaches the
        # target process. See start_stealth.sh / patch_frida.py.
        if self.args.remote:
            try:
                mgr = frida.get_device_manager()
                self.device = mgr.add_remote_device(self.args.remote)
                # Force a roundtrip so a bad host:port fails fast here
                # rather than during attach/spawn.
                self.device.enumerate_processes()
                print(f"[+] Stealth frida server conectado: "
                      f"{colorize(self.args.remote, BOLD)}")
                return True
            except Exception as e:
                print(f"[!] No se pudo conectar a {self.args.remote}: {e}")
                print("    Sugerencia: ejecuta ./start_stealth.sh primero.")
                return False
        try:
            self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Dispositivo conectado: {colorize(self.device.name, BOLD)}")
            return True
        except frida.InvalidArgumentError:
            print("[!] No se encontró dispositivo USB. Verifica la conexión y USB Debugging.")
            return False
        except Exception as e:
            print(f"[!] Error al conectar: {e}")
            return False

    # -- App listing --

    def list_apps(self):
        # Use adb directly -- avoids Frida's Java helper which crashes on MIUI
        print(colorize("\n=== Procesos en ejecución (adb ps) ===", BOLD))
        ps_out = self._adb("su", "-c", "ps -A | grep -v ' S 0' | awk '{print $1, $2, $9}'")
        print(f"\n{'PID':>7}  {'Name'}")
        print("-" * 60)
        lines = [l for l in ps_out.splitlines() if l.strip()]
        for line in sorted(lines, key=lambda x: x.split()[-1] if x.split() else ""):
            parts = line.split()
            if len(parts) >= 2:
                pid = parts[1]
                name = parts[-1]
                print(f"{colorize(f'{pid:>7}', Fore.GREEN if HAS_COLOR else '')}  {name}")
        print(f"\nTotal: {len(lines)} procesos")

        print(colorize("\n=== Apps instaladas (pm list packages) ===", BOLD))
        pm_out = self._adb("pm", "list", "packages")
        packages = sorted([l.replace("package:", "") for l in pm_out.splitlines() if l.startswith("package:")])
        for pkg in packages:
            print(f"  {pkg}")
        print(f"\nTotal: {len(packages)} paquetes instalados")

    # -- Message handler --

    def on_message(self, message, data):
        if message["type"] == "error":
            print(colorize(f"[!] Frida error: {message.get('description', '')} -- {message.get('stack', '')[:200]}", RED))
            return

        if message["type"] != "send":
            return

        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        event_type = payload.get("type", "")
        if event_type == "__INIT__":
            print(colorize(f"    [+] {payload.get('value', '')}", DIM))
            return

        self.event_count += 1

        # Console output
        print(format_event(payload))

        # File output
        if self.log_file:
            record = dict(payload)
            record["timestamp"] = datetime.now().isoformat()
            self.log_file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.log_file.flush()

    # -- Session management --

    def _attach_session(self, pid: int) -> bool:
        try:
            self.session = self.device.attach(pid)
            self.session.on("detached", self._on_detached)
            return True
        except frida.ProcessNotFoundError:
            print(f"[!] Proceso {pid} no encontrado.")
            return False
        except frida.TransportError as e:
            print(f"[!] Error de transporte al adjuntarse: {e}")
            return False

    def _on_detached(self, reason, crash):
        print(colorize(f"\n[!] Sesión desconectada: {reason}", RED))
        if crash:
            print(colorize(f"    Crash: {crash}", RED))

    def _load_scripts(self, layers: list[str], staggered: bool = False) -> bool:
        if staggered and len(layers) > 1:
            # Separate scanner from main layers — scanner is heavy and loads last
            main_layers = [l for l in layers if l != "scanner"]
            has_scanner = "scanner" in layers
            self._pending_scanner = has_scanner

            # Load main layers one by one with delay
            for layer in main_layers:
                js = load_hooks([layer])
                if not js:
                    print(f"[!] No se pudo cargar hook: {layer}")
                    continue
                try:
                    script = self.session.create_script(js)
                    script.on("message", self.on_message)
                    script.load()
                    self.scripts.append(script)
                    print(f"    [+] Capa '{layer}' inyectada")
                    time.sleep(4)  # 4s between layers to let ART stabilize
                except (frida.InvalidOperationError, frida.TransportError) as e:
                    print(f"[!] Error al cargar capa '{layer}': {e}")
                    continue
            return len(self.scripts) > 0
        else:
            js = load_hooks(layers)
            if not js:
                print("[!] No se pudo cargar ningún hook script.")
                return False
            try:
                script = self.session.create_script(js)
                script.on("message", self.on_message)
                script.load()
                self.scripts.append(script)
                return True
            except frida.InvalidOperationError as e:
                print(f"[!] Error al cargar script: {e}")
                return False

    def _load_scanner_deferred(self):
        """Load scanner layer after main monitoring is running."""
        if not getattr(self, '_pending_scanner', False):
            return
        self._pending_scanner = False
        print(colorize("\n[*] Cargando scanner en background (puede tomar ~10s)...", DIM))
        js = load_hooks(["scanner"])
        if not js:
            return
        try:
            script = self.session.create_script(js)
            script.on("message", self.on_message)
            script.load()
            self.scripts.append(script)
            print(colorize("    [+] Capa 'scanner' inyectada\n", DIM))
        except (frida.InvalidOperationError, frida.TransportError) as e:
            print(f"[!] Scanner no se pudo cargar (no crítico): {e}")

    def _miui_fix(self):
        """Create missing MIUI theme_compatibility.xml that crashes Frida's helper."""
        try:
            import subprocess
            subprocess.run(
                ["adb", "shell", "su", "-c",
                 "mkdir -p /data/system/theme_config && "
                 "[ -f /data/system/theme_config/theme_compatibility.xml ] || "
                 "cp /system/media/theme/theme_compatibility.xml "
                 "/data/system/theme_config/theme_compatibility.xml 2>/dev/null || "
                 "echo '<theme_compatibility version=\"140\"/>' > "
                 "/data/system/theme_config/theme_compatibility.xml"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    def spawn_and_hook(self, package: str, layers: list[str]) -> bool:
        self._miui_fix()

        # Kill existing instance
        try:
            self.device.kill(package)
            time.sleep(0.5)
        except Exception:
            pass

        try:
            pid = self.device.spawn([package])
            print(f"[+] Proceso iniciado (PID {pid})")
        except frida.ProcessNotFoundError:
            print(f"[!] Paquete no encontrado: {package}")
            return False
        except Exception as e:
            print(f"[!] Error al iniciar proceso: {e}")
            return False

        if not self._attach_session(pid):
            return False

        print(f"[+] Cargando hooks en capas: {', '.join(layers)}")
        if not self._load_scripts(layers):
            return False

        self.device.resume(pid)
        print(f"[+] App reanudada. Monitoreando {colorize(package, BOLD)}...")
        return True

    def attach_and_hook(self, package: str, layers: list[str]) -> bool:
        # Get PID via adb to avoid calling Frida's enumerate_processes (crashes on MIUI)
        pid_str = self._adb("su", "-c", f"pidof {package}")
        pid = None
        if pid_str:
            try:
                pid = int(pid_str.split()[0])
            except (ValueError, IndexError):
                pass

        if pid is None:
            print(f"[!] '{package}' no esta corriendo.")
            print(f"    Abre la app en el telefono y vuelve a ejecutar este comando.")
            return False

        print(f"[+] Adjuntando a '{package}' (PID {pid})")
        if not self._attach_session(pid):
            return False

        print(f"[+] Cargando hooks en capas (staggered): {', '.join(layers)}")
        return self._load_scripts(layers, staggered=True)

    # -- Main monitor loop --

    def monitor(self):
        print(colorize("\n[*] Monitoring active. Ctrl+C para detener.\n", BOLD))
        # Load scanner deferred after main hooks are stable
        self._load_scanner_deferred()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()

    def _cleanup(self):
        print(f"\n[+] Deteniendo... ({self.event_count} eventos capturados)")
        for script in self.scripts:
            try:
                script.unload()
            except Exception:
                pass
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
        if self.log_file:
            self.log_file.close()
            print(f"[+] Log guardado en: {self.args.output}")

    # -- Entry point --

    def run(self):
        if not self.connect():
            sys.exit(1)

        if self.args.list_apps:
            self.list_apps()
            return

        if not self.args.package:
            print("[!] Especifica --package <nombre.paquete> o usa --list-apps")
            sys.exit(1)

        # Parse layers
        all_layers = ["java", "native", "binder", "scanner"]
        if self.args.layers:
            layers = [l.strip().lower() for l in self.args.layers.split(",")]
            invalid = [l for l in layers if l not in all_layers]
            if invalid:
                print(f"[!] Capas inválidas: {invalid}. Usa: java, native, binder, scanner")
                sys.exit(1)
        else:
            layers = all_layers

        # Open log file
        if self.args.output:
            try:
                self.log_file = open(self.args.output, "a", encoding="utf-8")
            except OSError as e:
                print(f"[!] No se puede abrir archivo de log: {e}")
                sys.exit(1)

        # Connect hooks
        if self.args.attach:
            ok = self.attach_and_hook(self.args.package, layers)
        else:
            ok = self.spawn_and_hook(self.args.package, layers)

        if not ok:
            sys.exit(1)

        self.monitor()


# --- CLI ---------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="android_monitor.py",
        description="Monitor de identificadores Android en 3 capas usando Frida",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Listar apps instaladas / corriendo
  python android_monitor.py --list-apps

  # Monitorear una app desde el inicio (spawn)
  python android_monitor.py --package com.example.app --spawn

  # Adjuntarse a una app ya corriendo
  python android_monitor.py --package com.example.app --attach

  # Monitorear solo capas Java y Binder, guardando log
  python android_monitor.py --package com.example.app --spawn \\
      --layers java,binder --output report.jsonl

  # Monitorear todas las capas con log completo
  python android_monitor.py --package com.example.app --spawn \\
      --layers java,native,binder --output report.jsonl
        """
    )

    p.add_argument(
        "--package", "-p",
        metavar="PKG",
        help="Nombre del paquete Android (ej: com.whatsapp)"
    )
    p.add_argument(
        "--spawn",
        action="store_true",
        default=True,
        help="Iniciar la app desde cero e inyectar hooks (por defecto)"
    )
    p.add_argument(
        "--attach", "-a",
        action="store_true",
        default=False,
        help="Adjuntarse a un proceso ya en ejecución"
    )
    p.add_argument(
        "--layers", "-l",
        metavar="LAYERS",
        default=None,
        help="Capas a monitorear separadas por coma: java,native,binder,scanner (por defecto: todas)"
    )
    p.add_argument(
        "--output", "-o",
        metavar="FILE",
        default=None,
        help="Archivo de salida en formato JSON Lines (.jsonl)"
    )
    p.add_argument(
        "--list-apps",
        action="store_true",
        default=False,
        help="Listar aplicaciones en el dispositivo y salir"
    )
    p.add_argument(
        "--remote", "-H",
        metavar="HOST:PORT",
        default=None,
        help="Conectar al frida-server stealth via TCP (ej: 127.0.0.1:8443). "
             "Por defecto usa USB. Usa esto cuando frida-server fue lanzado "
             "con start_stealth.sh para evadir detección de Snapchat/anti-Frida."
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --attach overrides --spawn default
    if args.attach:
        args.spawn = False

    print(colorize("\n  Android 4-Layer Identifier Monitor", BOLD))
    print(colorize("  Frida-based | Java + Native + Binder + Scanner\n", DIM))

    monitor = AndroidMonitor(args)
    monitor.run()


if __name__ == "__main__":
    main()
