/**
 * Layer 2 — Native C/C++ Hooks (Expanded)
 * Intercepts libc/libandroid/libEGL/libGLESv2/libvulkan system calls that
 * expose device identity at the native layer.
 *
 * Hooked functions:
 *   open / openat        — file access to /proc, /sys, battery, maps
 *   read                 — content reads from sensitive file descriptors
 *   stat / fstat / lstat / fstatat — metadata + timestamp queries
 *   access               — file existence probes (root, magisk, etc.)
 *   readlinkat / readlink — fd link resolution (memfd detection)
 *   execve               — child process execution
 *   ioctl                — device control (network interfaces)
 *   getifaddrs           — network interface enumeration
 *   recvmsg              — netlink interface enumeration (tun0 detection)
 *   uname                — kernel version
 *   sysinfo              — uptime, memory
 *   dlopen / android_dlopen_ext — dynamic library loading
 *   __system_property_get — system property queries (200+ keys)
 *   eglQueryString       — EGL vendor/version/extensions
 *   glGetString          — GL renderer/vendor/version
 */

(function () {

  var reported = {};
  function isNew(type, value) {
    var key = type + ":" + value;
    if (reported[key]) return false;
    reported[key] = true;
    return true;
  }

  // ─── Sensitive path filters ───────────────────────────────────────────────

  var SENSITIVE_PATHS = [
    "/proc/net", "/proc/self/net",
    "/sys/class/net", "/sys/class/power_supply",
    "mac_address", "/sys/block",
    "/proc/self/maps", "/proc/self/smaps",
    "/proc/self/status", "/proc/self/stat",
    "/proc/self/cmdline", "/proc/self/mountinfo",
    "/proc/self/mounts", "/proc/self/fd",
    "/proc/cpuinfo", "/proc/version", "/proc/cmdline",
    "/dev/binder", "/dev/hwbinder",
    "/data/data", "/data/adb",
    "serial", "imei", "gsm", "telephony",
    "magisk", "supersu", "su", "busybox",
    "/sys/fs/selinux", "zygisk",
    "/proc/self/exe",
    "battery/temp", "battery/voltage",
    "battery/status", "battery/health",
    // A13+ APEX-relocated libs + new sensitive paths
    "/apex/com.android.art/", "/apex/com.android.adbd/",
    "/apex/com.android.tethering/", "/apex/com.android.bluetooth/",
    "/apex/com.android.uwb/", "/apex/com.android.nfcservices/",
    "/apex/com.android.healthfitness/", "/apex/com.android.ondevicepersonalization/",
    // USB device enumeration (VID/PID leaks SoC vendor)
    "/sys/bus/usb/devices", "/sys/devices/platform/soc",
    // Storage UUIDs
    "/proc/mounts", "/proc/partitions",
    // 5G / modem IDs
    "/sys/devices/platform/IPA",
    // Health Connect
    "/data/misc/health_connect",
    // Widevine / DRM
    "/data/vendor/mediadrm", "/persist/data/md_","/data/vendor/widevine"
  ];

  // Expanded property list — all keys OmniShield intercepts
  // v1.52.2 additions: PR-Sprint1-L2.1 serial variants + PR-Sprint2 build-id partitions
  // + PR-Sprint2.1 ro.bootimage.build.fingerprint siblings. Keep this list in sync with
  // the key list in `my_system_property_get` (jni/main.cpp) — any new hooked key MUST
  // appear here or OmniTracker will miss the emit and the value won't be visible in logs.
  var SENSITIVE_PROPS = [
    // Identity (serial variants — PR-Sprint1-L2.1 expanded from 4 to 6 keys)
    "ro.serialno", "ro.boot.serialno",
    "persist.sys.serial", "persist.sys.serialno",   // both forms tracked
    "ril.serialnumber",
    "ro.vendor.product.serial", "vendor.serialno",  // v1.52 Sprint 1 L2.1 additions
    "ro.product.model", "ro.product.manufacturer", "ro.product.brand",
    "ro.product.device", "ro.product.name", "ro.product.board",
    // Partitioned identity (system, vendor, odm, product, system_ext)
    "ro.product.system.model", "ro.product.vendor.model", "ro.product.odm.model",
    "ro.product.system.manufacturer", "ro.product.vendor.manufacturer",
    "ro.product.system.brand", "ro.product.vendor.brand",
    "ro.product.system.device", "ro.product.vendor.device",
    "ro.product.system.name", "ro.product.vendor.name",
    // for_attestation namespace
    "ro.product.model_for_attestation", "ro.product.brand_for_attestation",
    "ro.product.name_for_attestation", "ro.product.device_for_attestation",
    // Fingerprints — PR-Sprint1-L3.2: 7 variants (bootimage added in v1.52)
    "ro.build.fingerprint", "ro.bootimage.build.fingerprint",
    "ro.vendor.build.fingerprint", "ro.odm.build.fingerprint",
    "ro.system.build.fingerprint", "ro.system_ext.build.fingerprint",
    "ro.product.build.fingerprint",
    // Build IDs — PR-Sprint2 S2-A (ro.build.id) + PR-Sprint2.1 C7 (6 partition siblings)
    // All 7 must return kCoherentBuildId to stay coherent with the 7 fingerprint variants.
    "ro.build.id",
    "ro.bootimage.build.id", "ro.vendor.build.id", "ro.odm.build.id",
    "ro.system.build.id", "ro.system_ext.build.id", "ro.product.build.id",
    // Build metadata (ro.build.tags/ro.build.type explicitly hooked in PR-Sprint2.1 C6)
    "ro.build.display.id", "ro.build.host", "ro.build.user",
    "ro.build.flavor", "ro.build.tags", "ro.build.type",
    "ro.build.description", "ro.build.version.incremental",
    "ro.build.version.security_patch", "ro.build.version.release",
    "ro.build.version.codename", "ro.build.version.preview_sdk",
    "ro.build.date.utc", "ro.build.date",
    // Hardware
    "ro.hardware", "ro.board.platform", "ro.boot.hardware",
    "ro.hardware.chipname", "ro.soc.manufacturer", "ro.soc.model",
    "ro.boot.bootdevice",
    // HAL
    "ro.hardware.gralloc", "ro.hardware.hwcomposer", "ro.hardware.camera",
    "ro.hardware.keystore", "ro.hardware.audio", "ro.hardware.vulkan",
    "ro.hardware.egl",
    // Security
    "ro.secure", "ro.debuggable", "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
    "ro.secureboot.lockstate", "ro.oem_unlock_supported",
    "sys.oem_unlock_allowed",
    // Telephony
    "gsm.network.type", "gsm.sim.state", "gsm.version.baseband",
    "gsm.version.ril-impl", "gsm.sim.operator.numeric",
    "gsm.sim.operator.iso-country", "gsm.sim.operator.alpha",
    "gsm.operator.numeric", "gsm.operator.iso-country", "gsm.operator.alpha",
    "gsm.device.id", "ro.telephony.default_network", "ro.carrier",
    // IMEI
    "ro.ril.miui.imei0", "ro.ril.miui.imei1", "ro.ril.oem.imei",
    // DRM
    "ro.mediadrm.device_id", "drm.service.enabled",
    // Display
    "ro.sf.lcd_density", "ro.opengles.version",
    // Locale
    "ro.product.locale", "persist.sys.locale", "persist.sys.timezone",
    "persist.sys.country", "persist.sys.language",
    // Network
    "net.hostname", "wifi.interface",
    // MediaTek / MIUI suppression
    "ro.mediatek.version.branch", "ro.vendor.mediatek.platform.hardware",
    "ro.miui.ui.version.name", "ro.miui.ui.version.code",
    // Zygote
    "ro.zygote",
    // Market name
    "ro.product.marketname", "ro.product.vendor.marketname",
    // A13+ extensions — SDK extension levels, privacy sandbox, UWB/NFC HAL
    "build.version.extensions.r", "build.version.extensions.s",
    "build.version.extensions.t", "build.version.extensions.u",
    "build.version.extensions.ad_services",
    "ro.build.version.sdk_int_full", "ro.build.version.known_codenames",
    "ro.hardware.uwb", "ro.hardware.nfc", "ro.hardware.bluetooth",
    "ro.boot.bootreason", "ro.boot.boottime",
    // Qualcomm / MediaTek modem identifiers seen on A13+ builds
    "ro.vendor.qti.telephony.service_enabled",
    "ro.vendor.mediatek.telephony.service_enabled",
    "ro.telephony.iwlan_operation_mode",
    // Widevine provisioning
    "drm.mediadrm.widevine.version",
    "ro.mediadrm.widevine.version", "ro.vendor.widevine.version",
    // 5G radio state
    "persist.radio.5g_nr_enabled", "persist.radio.data_con_rat",
    "gsm.cell.identity_5g",
    // Privacy sandbox / on-device personalization (A13+)
    "ro.ad_services.version",
    // Virtualization (A13+)
    "ro.boot.vbmeta.digest",
    "persist.sys.virtualization"
  ];

  function isSensitivePath(path) {
    if (!path) return false;
    var lower = path.toLowerCase();
    for (var i = 0; i < SENSITIVE_PATHS.length; i++) {
      if (lower.indexOf(SENSITIVE_PATHS[i]) !== -1) return true;
    }
    return false;
  }

  function isSensitiveProp(name) {
    if (!name) return false;
    var lower = name.toLowerCase();
    for (var i = 0; i < SENSITIVE_PROPS.length; i++) {
      if (lower === SENSITIVE_PROPS[i]) return true;
    }
    return false;
  }

  function emit(type, value, extra) {
    var payload = {
      layer: "native",
      type: type,
      value: value !== undefined && value !== null ? String(value) : null,
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    try {
      payload.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(function (s) { return s.toString(); })
        .slice(0, 5);
    } catch (e) {
      payload.backtrace = [];
    }
    send(payload);
  }

  function readCStr(ptr) {
    try { if (ptr.isNull()) return null; return ptr.readCString(); } catch (e) { return null; }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE I/O — open, openat, read
  // ═══════════════════════════════════════════════════════════════════════════

  var sensitiveFds = {};

  var openPtr = Module.findExportByName("libc.so", "open");
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) { this.path = readCStr(args[0]); this.flags = args[1].toInt32(); },
      onLeave: function (retval) {
        var fd = retval.toInt32();
        if (fd >= 0 && isSensitivePath(this.path)) {
          sensitiveFds[fd] = this.path;
          if (isNew("FILE_OPEN", this.path)) {
            emit.call(this, "FILE_OPEN", this.path, { fd: fd, flags: this.flags });
          }
        }
      }
    });
  }

  var openatPtr = Module.findExportByName("libc.so", "openat");
  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter: function (args) { this.path = readCStr(args[1]); this.flags = args[2].toInt32(); },
      onLeave: function (retval) {
        var fd = retval.toInt32();
        if (fd >= 0 && isSensitivePath(this.path)) {
          sensitiveFds[fd] = this.path;
          if (isNew("FILE_OPEN", this.path)) {
            emit.call(this, "FILE_OPEN", this.path, { fd: fd, flags: this.flags, syscall: "openat" });
          }
        }
      }
    });
  }

  var readPtr = Module.findExportByName("libc.so", "read");
  if (readPtr) {
    Interceptor.attach(readPtr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32(); this.buf = args[1]; this.count = args[2].toInt32();
      },
      onLeave: function (retval) {
        var n = retval.toInt32();
        if (n > 0 && sensitiveFds[this.fd]) {
          try {
            var content = this.buf.readUtf8String(Math.min(n, 1024));
            emit.call(this, "FILE_READ", content, {
              fd: this.fd, path: sensitiveFds[this.fd], bytesRead: n
            });
            delete sensitiveFds[this.fd];
          } catch (e) {}
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STAT — stat, lstat, fstat, fstatat (timestamps)
  // ═══════════════════════════════════════════════════════════════════════════

  var statFuncs = ["stat", "lstat", "fstatat"];
  for (var si = 0; si < statFuncs.length; si++) {
    (function(fname) {
      var ptr = Module.findExportByName("libc.so", fname);
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter: function (args) {
            this.path = fname === "fstatat" ? readCStr(args[1]) : readCStr(args[0]);
          },
          onLeave: function (retval) {
            if (isSensitivePath(this.path) && isNew("FILE_STAT", fname + ":" + this.path)) {
              emit.call(this, "FILE_STAT", this.path, { syscall: fname, ret: retval.toInt32() });
            }
          }
        });
      }
    })(statFuncs[si]);
  }

  var fstatPtr = Module.findExportByName("libc.so", "fstat");
  if (fstatPtr) {
    Interceptor.attach(fstatPtr, {
      onEnter: function (args) { this.fd = args[0].toInt32(); },
      onLeave: function (retval) {
        if (sensitiveFds[this.fd] && isNew("FILE_STAT", "fstat:" + this.fd)) {
          emit.call(this, "FILE_STAT", sensitiveFds[this.fd], { syscall: "fstat", fd: this.fd });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ACCESS — file existence probes (root detection)
  // ═══════════════════════════════════════════════════════════════════════════

  var ROOT_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/su/bin/su", "/data/local/su", "/data/local/bin/su",
    "/system/app/Superuser.apk", "/system/app/SuperSU",
    "/data/adb/magisk", "/data/adb/modules",
    "/system/bin/magisk", "/sbin/.magisk",
    "/dev/su", "/proc/self/maps"
  ];

  var accessPtr = Module.findExportByName("libc.so", "access");
  if (accessPtr) {
    Interceptor.attach(accessPtr, {
      onEnter: function (args) { this.path = readCStr(args[0]); this.mode = args[1].toInt32(); },
      onLeave: function (retval) {
        if (!this.path) return;
        var lower = this.path.toLowerCase();
        var isRoot = false;
        for (var i = 0; i < ROOT_PATHS.length; i++) {
          if (lower.indexOf(ROOT_PATHS[i]) !== -1) { isRoot = true; break; }
        }
        if ((isRoot || isSensitivePath(this.path)) && isNew("FILE_ACCESS", this.path)) {
          emit.call(this, "FILE_ACCESS", this.path, {
            mode: this.mode, exists: retval.toInt32() === 0,
            isRootProbe: isRoot
          });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // READLINKAT / READLINK — memfd detection, fd resolution
  // ═══════════════════════════════════════════════════════════════════════════

  var readlinkatPtr = Module.findExportByName("libc.so", "readlinkat");
  if (readlinkatPtr) {
    Interceptor.attach(readlinkatPtr, {
      onEnter: function (args) {
        this.path = readCStr(args[1]);
        this.buf = args[2];
        this.bufsiz = args[3].toInt32();
      },
      onLeave: function (retval) {
        var n = retval.toInt32();
        if (n > 0 && this.path && this.path.indexOf("/proc/self/fd/") !== -1) {
          try {
            var target = this.buf.readUtf8String(n);
            if (target.indexOf("memfd") !== -1 || target.indexOf("/dev/ashmem") !== -1) {
              if (isNew("READLINK_FD", this.path + "=" + target)) {
                emit.call(this, "READLINK_FD", target, {
                  fdPath: this.path,
                  isMemfd: target.indexOf("memfd") !== -1
                });
              }
            }
          } catch (e) {}
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UNAME — kernel version
  // ═══════════════════════════════════════════════════════════════════════════

  var unamePtr = Module.findExportByName("libc.so", "uname");
  if (unamePtr) {
    Interceptor.attach(unamePtr, {
      onEnter: function (args) { this.buf = args[0]; },
      onLeave: function (retval) {
        if (retval.toInt32() === 0 && this.buf) {
          try {
            // struct utsname: sysname(65) + nodename(65) + release(65) + version(65) + machine(65)
            var sysname  = this.buf.readCString();
            var nodename = this.buf.add(65).readCString();
            var release  = this.buf.add(130).readCString();
            var version  = this.buf.add(195).readCString();
            var machine  = this.buf.add(260).readCString();
            if (isNew("UNAME", release)) {
              emit.call(this, "UNAME", release, {
                sysname: sysname, nodename: nodename,
                release: release, version: version, machine: machine
              });
            }
          } catch (e) {}
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SYSINFO — uptime, total/free RAM
  // ═══════════════════════════════════════════════════════════════════════════

  var sysinfoPtr = Module.findExportByName("libc.so", "sysinfo");
  if (sysinfoPtr) {
    Interceptor.attach(sysinfoPtr, {
      onEnter: function (args) { this.buf = args[0]; },
      onLeave: function (retval) {
        if (retval.toInt32() === 0 && this.buf) {
          try {
            var uptime = this.buf.readS64();
            var totalram = this.buf.add(32).readU64();
            if (isNew("SYSINFO", "uptime")) {
              emit.call(this, "SYSINFO", String(uptime) + "s uptime", {
                uptime: uptime.toString(),
                totalram: totalram.toString()
              });
            }
          } catch (e) {}
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EXECVE
  // ═══════════════════════════════════════════════════════════════════════════

  var execvePtr = Module.findExportByName("libc.so", "execve");
  if (execvePtr) {
    Interceptor.attach(execvePtr, {
      onEnter: function (args) {
        var path = readCStr(args[0]);
        var argv = [];
        try {
          var argvPtr = args[1];
          for (var i = 0; i < 16; i++) {
            var argPtr = argvPtr.add(i * Process.pointerSize).readPointer();
            if (argPtr.isNull()) break;
            argv.push(readCStr(argPtr));
          }
        } catch (e) {}
        emit.call(this, "PROCESS_EXEC", path, { argv: argv.join(" ") });
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IOCTL — network interface queries
  // ═══════════════════════════════════════════════════════════════════════════

  var BINDER_WRITE_READ = 0xC0306201;
  var INTERESTING_IOCTLS = [0x8915, 0x8927, 0x8913, 0x8912]; // SIOCGIFADDR/HWADDR/NAME/CONF

  var ioctlPtr = Module.findExportByName("libc.so", "ioctl");
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32(); this.request = args[1].toUInt32();
      },
      onLeave: function (retval) {
        if (this.request === BINDER_WRITE_READ) return;
        for (var i = 0; i < INTERESTING_IOCTLS.length; i++) {
          if (this.request === INTERESTING_IOCTLS[i]) {
            if (isNew("IOCTL_NETWORK", this.request)) {
              emit.call(this, "IOCTL_NETWORK", "0x" + this.request.toString(16), {
                fd: this.fd, ret: retval.toInt32()
              });
            }
            break;
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GETIFADDRS — network interface enumeration
  // ═══════════════════════════════════════════════════════════════════════════

  var getifaddrsPtr = Module.findExportByName("libc.so", "getifaddrs");
  if (getifaddrsPtr) {
    Interceptor.attach(getifaddrsPtr, {
      onEnter: function (args) { this.ifap = args[0]; },
      onLeave: function (retval) {
        if (retval.toInt32() === 0) {
          // Walk the linked list to enumerate interfaces
          var ifaces = [];
          try {
            var ptr = this.ifap.readPointer();
            for (var count = 0; count < 50 && !ptr.isNull(); count++) {
              var name = ptr.readPointer().readCString();
              if (name && ifaces.indexOf(name) === -1) ifaces.push(name);
              ptr = ptr.add(Process.pointerSize).readPointer(); // ifa_next is second field
              // This is approximate — struct layout varies
              break; // Just report the call for safety
            }
          } catch (e) {}
          if (isNew("GETIFADDRS", "call")) {
            emit.call(this, "GETIFADDRS", ifaces.join(",") || "enumerated", {
              interfaces: ifaces
            });
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RECVMSG — netlink interface enumeration (tun0 detection bypass)
  // ═══════════════════════════════════════════════════════════════════════════

  var recvmsgPtr = Module.findExportByName("libc.so", "recvmsg");
  if (recvmsgPtr) {
    Interceptor.attach(recvmsgPtr, {
      onEnter: function (args) {
        this.sockfd = args[0].toInt32();
        this.msg = args[1];
      },
      onLeave: function (retval) {
        var n = retval.toInt32();
        if (n <= 0) return;
        try {
          // Check if this is a netlink socket (AF_NETLINK = 16)
          var msgName = this.msg.add(0).readPointer();
          if (!msgName.isNull()) {
            var family = msgName.readU16();
            if (family === 16) { // AF_NETLINK
              if (isNew("RECVMSG_NETLINK", this.sockfd)) {
                emit.call(this, "RECVMSG_NETLINK", "AF_NETLINK recvmsg", {
                  sockfd: this.sockfd, bytesReceived: n,
                  note: "Netlink interface enumeration — OmniShield filters tun0 here"
                });
              }
            }
          }
        } catch (e) {}
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DLOPEN
  // ═══════════════════════════════════════════════════════════════════════════

  var dlopenPtr = Module.findExportByName("libdl.so", "dlopen");
  if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
      onEnter: function (args) { this.lib = readCStr(args[0]); },
      onLeave: function (retval) {
        if (this.lib && isNew("DLOPEN", this.lib)) {
          emit.call(this, "DLOPEN", this.lib, { handle: retval.toString() });
        }
      }
    });
  }

  var androidDlopenExtPtr = Module.findExportByName("libdl.so", "android_dlopen_ext");
  if (androidDlopenExtPtr) {
    Interceptor.attach(androidDlopenExtPtr, {
      onEnter: function (args) { this.lib = readCStr(args[0]); },
      onLeave: function (retval) {
        if (this.lib && isNew("DLOPEN", this.lib)) {
          emit.call(this, "DLOPEN", this.lib, { method: "android_dlopen_ext", handle: retval.toString() });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SYSTEM PROPERTIES — __system_property_get (capture ALL, not just filtered)
  // ═══════════════════════════════════════════════════════════════════════════

  var propGetPtr = Module.findExportByName("libc.so", "__system_property_get");
  if (propGetPtr) {
    Interceptor.attach(propGetPtr, {
      onEnter: function (args) {
        this.propName = readCStr(args[0]);
        this.valueBuf = args[1];
      },
      onLeave: function (retval) {
        if (isSensitiveProp(this.propName)) {
          var value = null;
          try { value = this.valueBuf.readCString(); } catch (e) {}
          if (isNew("SYSTEM_PROPERTY", this.propName)) {
            emit.call(this, "SYSTEM_PROPERTY", value, { property: this.propName });
          }
        }
      }
    });
  }

  var libcutilsPropGet = Module.findExportByName("libcutils.so", "property_get");
  if (libcutilsPropGet) {
    Interceptor.attach(libcutilsPropGet, {
      onEnter: function (args) { this.propName = readCStr(args[0]); this.valueBuf = args[1]; },
      onLeave: function (retval) {
        if (isSensitiveProp(this.propName) && isNew("SYSTEM_PROPERTY", this.propName)) {
          var value = null;
          try { value = this.valueBuf.readCString(); } catch (e) {}
          emit.call(this, "SYSTEM_PROPERTY", value, { property: this.propName, lib: "libcutils" });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EGL — GPU identity strings
  // ═══════════════════════════════════════════════════════════════════════════

  var eglQueryStringPtr = Module.findExportByName("libEGL.so", "eglQueryString");
  if (eglQueryStringPtr) {
    Interceptor.attach(eglQueryStringPtr, {
      onEnter: function (args) {
        this.dpy = args[0];
        this.name = args[1].toInt32();
      },
      onLeave: function (retval) {
        if (!retval.isNull()) {
          var names = { 0x3053: "EGL_VENDOR", 0x3054: "EGL_VERSION",
                        0x3055: "EGL_EXTENSIONS", 0x308D: "EGL_CLIENT_APIS" };
          var nameStr = names[this.name] || "0x" + this.name.toString(16);
          var val = retval.readCString();
          if (val && isNew("EGL", nameStr)) {
            emit.call(this, "EGL", val.substring(0, 200), { query: nameStr });
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GLES — GL renderer/vendor/version
  // ═══════════════════════════════════════════════════════════════════════════

  var glGetStringPtr = Module.findExportByName("libGLESv2.so", "glGetString");
  if (glGetStringPtr) {
    Interceptor.attach(glGetStringPtr, {
      onEnter: function (args) { this.name = args[0].toInt32(); },
      onLeave: function (retval) {
        if (!retval.isNull()) {
          var names = { 0x1F00: "GL_VENDOR", 0x1F01: "GL_RENDERER",
                        0x1F02: "GL_VERSION", 0x1F03: "GL_EXTENSIONS" };
          var nameStr = names[this.name] || "0x" + this.name.toString(16);
          var val = retval.readCString();
          if (val && isNew("GL", nameStr)) {
            emit.call(this, "GL", val.substring(0, 200), { query: nameStr });
          }
        }
      }
    });
  }

  // Also try libGLESv1_CM.so for legacy GL
  var glGetStringV1Ptr = Module.findExportByName("libGLESv1_CM.so", "glGetString");
  if (glGetStringV1Ptr && glGetStringV1Ptr.toString() !== (glGetStringPtr ? glGetStringPtr.toString() : "")) {
    Interceptor.attach(glGetStringV1Ptr, {
      onEnter: function (args) { this.name = args[0].toInt32(); },
      onLeave: function (retval) {
        if (!retval.isNull()) {
          var names = { 0x1F00: "GL_VENDOR", 0x1F01: "GL_RENDERER", 0x1F02: "GL_VERSION" };
          var nameStr = names[this.name] || "0x" + this.name.toString(16);
          var val = retval.readCString();
          if (val && isNew("GL_V1", nameStr)) {
            emit.call(this, "GL", val.substring(0, 200), { query: nameStr, lib: "GLESv1_CM" });
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DL_ITERATE_PHDR — module enumeration (stealth detection)
  // ═══════════════════════════════════════════════════════════════════════════

  var dlIteratePhdrPtr = Module.findExportByName("libc.so", "dl_iterate_phdr");
  if (dlIteratePhdrPtr) {
    Interceptor.attach(dlIteratePhdrPtr, {
      onEnter: function (args) {
        if (isNew("DL_ITERATE_PHDR", "call")) {
          emit.call(this, "DL_ITERATE_PHDR", "module enumeration called", {
            note: "Used to detect injected modules in memory"
          });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MMAP / MPROTECT — memory mapping detection (Frida/module injection)
  // ═══════════════════════════════════════════════════════════════════════════

  var mmapPtr = Module.findExportByName("libc.so", "mmap");
  if (mmapPtr) {
    Interceptor.attach(mmapPtr, {
      onEnter: function (args) {
        this.addr = args[0];
        this.length = args[1].toUInt32();
        this.prot = args[2].toInt32();
        this.flags = args[3].toInt32();
        this.fd = args[4].toInt32();
      },
      onLeave: function (retval) {
        // Only log executable mappings (PROT_EXEC = 4)
        if (this.prot & 4) {
          var path = sensitiveFds[this.fd] || null;
          if (isNew("MMAP_EXEC", this.fd + ":" + this.length)) {
            emit.call(this, "MMAP_EXEC", path || "fd=" + this.fd, {
              length: this.length, prot: this.prot, flags: this.flags,
              fd: this.fd, addr: retval.toString()
            });
          }
        }
      }
    });
  }

  var mprotectPtr = Module.findExportByName("libc.so", "mprotect");
  if (mprotectPtr) {
    Interceptor.attach(mprotectPtr, {
      onEnter: function (args) {
        this.addr = args[0];
        this.len = args[1].toUInt32();
        this.prot = args[2].toInt32();
      },
      onLeave: function (retval) {
        // Log when something is made executable (RWX = 7 or RX = 5)
        if ((this.prot & 4) && (this.prot & 2)) {
          if (isNew("MPROTECT_RWX", this.addr.toString())) {
            emit.call(this, "MPROTECT_RWX", this.addr.toString(), {
              length: this.len, prot: this.prot,
              note: "RWX memory — possible code injection"
            });
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CONNECT / SENDTO — network socket connections
  // ═══════════════════════════════════════════════════════════════════════════

  var connectPtr = Module.findExportByName("libc.so", "connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.addr = args[1];
        this.addrlen = args[2].toInt32();
      },
      onLeave: function (retval) {
        try {
          var family = this.addr.readU16();
          if (family === 2 && this.addrlen >= 16) { // AF_INET
            var port = (this.addr.add(2).readU8() << 8) | this.addr.add(3).readU8();
            var ip = this.addr.add(4).readU8() + "." +
                     this.addr.add(5).readU8() + "." +
                     this.addr.add(6).readU8() + "." +
                     this.addr.add(7).readU8();
            if (isNew("CONNECT", ip + ":" + port)) {
              emit.call(this, "CONNECT", ip + ":" + port, {
                fd: this.fd, family: "AF_INET", ip: ip, port: port,
                ret: retval.toInt32()
              });
            }
          } else if (family === 10 && this.addrlen >= 28) { // AF_INET6
            var port6 = (this.addr.add(2).readU8() << 8) | this.addr.add(3).readU8();
            if (isNew("CONNECT6", this.fd + ":" + port6)) {
              emit.call(this, "CONNECT", "[::]:" + port6, {
                fd: this.fd, family: "AF_INET6", port: port6,
                ret: retval.toInt32()
              });
            }
          } else if (family === 1) { // AF_UNIX
            var sockPath = readCStr(this.addr.add(2));
            if (sockPath && isNew("CONNECT_UNIX", sockPath)) {
              emit.call(this, "CONNECT_UNIX", sockPath, {
                fd: this.fd, family: "AF_UNIX"
              });
            }
          }
        } catch (e) {}
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRCTL — process control (PR_SET_DUMPABLE, PR_SET_NAME detection)
  // ═══════════════════════════════════════════════════════════════════════════

  var prctlPtr = Module.findExportByName("libc.so", "prctl");
  if (prctlPtr) {
    var PRCTL_NAMES = {
      1: "PR_SET_PDEATHSIG", 4: "PR_SET_DUMPABLE", 3: "PR_GET_DUMPABLE",
      15: "PR_SET_NAME", 16: "PR_GET_NAME", 22: "PR_SET_SECCOMP",
      36: "PR_SET_NO_NEW_PRIVS", 38: "PR_GET_NO_NEW_PRIVS"
    };
    Interceptor.attach(prctlPtr, {
      onEnter: function (args) {
        this.option = args[0].toInt32();
        this.arg2 = args[1];
      },
      onLeave: function (retval) {
        var name = PRCTL_NAMES[this.option];
        if (name && isNew("PRCTL", name)) {
          var extra = { option: this.option, optionName: name, ret: retval.toInt32() };
          if (this.option === 15) { // PR_SET_NAME
            try { extra.processName = readCStr(this.arg2); } catch (e) {}
          }
          emit.call(this, "PRCTL", name, extra);
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GETPID / GETPPID / GETTID — process identity queries
  // ═══════════════════════════════════════════════════════════════════════════

  var getpidPtr = Module.findExportByName("libc.so", "getpid");
  if (getpidPtr) {
    Interceptor.attach(getpidPtr, {
      onLeave: function (retval) {
        if (isNew("GETPID", "call")) {
          emit.call(this, "GETPID", retval.toInt32().toString());
        }
      }
    });
  }

  var getppidPtr = Module.findExportByName("libc.so", "getppid");
  if (getppidPtr) {
    Interceptor.attach(getppidPtr, {
      onLeave: function (retval) {
        if (isNew("GETPPID", "call")) {
          emit.call(this, "GETPPID", retval.toInt32().toString(), {
            note: "Parent PID — used for Zygote/tracer detection"
          });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PTRACE — anti-debugging detection
  // ═══════════════════════════════════════════════════════════════════════════

  var ptracePtr = Module.findExportByName("libc.so", "ptrace");
  if (ptracePtr) {
    Interceptor.attach(ptracePtr, {
      onEnter: function (args) {
        this.request = args[0].toInt32();
        this.pid = args[1].toInt32();
      },
      onLeave: function (retval) {
        var PTRACE_NAMES = { 0: "TRACEME", 1: "PEEKTEXT", 2: "PEEKDATA",
          16: "ATTACH", 17: "DETACH", 24: "SEIZE" };
        var name = PTRACE_NAMES[this.request] || "req=" + this.request;
        if (isNew("PTRACE", name + ":" + this.pid)) {
          emit.call(this, "PTRACE", name, {
            request: this.request, pid: this.pid,
            ret: retval.toInt32(),
            note: "Anti-debug: PTRACE_TRACEME prevents other debuggers"
          });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // OPENDIR / READDIR — /proc scanning for Frida/module detection
  // ═══════════════════════════════════════════════════════════════════════════

  var opendirPaths = {};

  var opendirPtr = Module.findExportByName("libc.so", "opendir");
  if (opendirPtr) {
    Interceptor.attach(opendirPtr, {
      onEnter: function (args) { this.path = readCStr(args[0]); },
      onLeave: function (retval) {
        if (!retval.isNull() && this.path) {
          var lower = this.path.toLowerCase();
          if (lower.indexOf("/proc") !== -1 || lower.indexOf("/data") !== -1 ||
              lower.indexOf("/system") !== -1) {
            opendirPaths[retval.toString()] = this.path;
            if (isNew("OPENDIR", this.path)) {
              emit.call(this, "OPENDIR", this.path);
            }
          }
        }
      }
    });
  }

  var readdirPtr = Module.findExportByName("libc.so", "readdir");
  if (readdirPtr) {
    Interceptor.attach(readdirPtr, {
      onEnter: function (args) { this.dirp = args[0]; },
      onLeave: function (retval) {
        if (!retval.isNull() && opendirPaths[this.dirp.toString()]) {
          try {
            // struct dirent: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(256)
            var dName = retval.add(19).readCString();
            var dirPath = opendirPaths[this.dirp.toString()];
            // Report /proc/PID scanning and suspicious directories
            if (dirPath.indexOf("/proc") !== -1 && /^\d+$/.test(dName)) {
              // Scanning PIDs in /proc — only report once
              if (isNew("READDIR_PROC_PID", "scanning")) {
                emit.call(this, "READDIR_PROC_PID", dirPath + "/" + dName, {
                  note: "Scanning /proc PIDs — Frida/module detection"
                });
              }
            }
          } catch (e) {}
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // KILL / SIGNAL — anti-debug signal sending
  // ═══════════════════════════════════════════════════════════════════════════

  var killPtr = Module.findExportByName("libc.so", "kill");
  if (killPtr) {
    Interceptor.attach(killPtr, {
      onEnter: function (args) {
        this.pid = args[0].toInt32();
        this.sig = args[1].toInt32();
        if (isNew("KILL", this.pid + ":" + this.sig)) {
          emit.call(this, "KILL", "pid=" + this.pid + " sig=" + this.sig, {
            pid: this.pid, signal: this.sig
          });
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SOCKET — socket creation tracking
  // ═══════════════════════════════════════════════════════════════════════════

  var socketPtr = Module.findExportByName("libc.so", "socket");
  if (socketPtr) {
    Interceptor.attach(socketPtr, {
      onEnter: function (args) {
        this.domain = args[0].toInt32();
        this.sockType = args[1].toInt32();
        this.protocol = args[2].toInt32();
      },
      onLeave: function (retval) {
        var domainNames = { 1: "AF_UNIX", 2: "AF_INET", 10: "AF_INET6", 16: "AF_NETLINK" };
        var domainName = domainNames[this.domain];
        if (domainName && this.domain === 16) { // AF_NETLINK — interface enumeration
          if (isNew("SOCKET_NETLINK", "create")) {
            emit.call(this, "SOCKET_NETLINK", domainName, {
              fd: retval.toInt32(), type: this.sockType, protocol: this.protocol,
              note: "Netlink socket — used for interface enumeration"
            });
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VULKAN — vkGetPhysicalDeviceProperties (GPU identity)
  // ═══════════════════════════════════════════════════════════════════════════

  var vulkanLib = Module.findExportByName("libvulkan.so", "vkGetPhysicalDeviceProperties");
  if (vulkanLib) {
    Interceptor.attach(vulkanLib, {
      onEnter: function (args) {
        this.physDev = args[0];
        this.props = args[1];
      },
      onLeave: function () {
        try {
          // VkPhysicalDeviceProperties: apiVersion(4) + driverVersion(4) + vendorID(4) + deviceID(4) + deviceType(4) + deviceName(256)
          var deviceName = this.props.add(20).readCString();
          var vendorID = this.props.add(8).readU32();
          var deviceID = this.props.add(12).readU32();
          if (isNew("VULKAN_DEVICE", deviceName)) {
            emit.call(this, "VULKAN_DEVICE", deviceName, {
              vendorID: "0x" + vendorID.toString(16),
              deviceID: "0x" + deviceID.toString(16)
            });
          }
        } catch (e) {}
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CLOSE — track fd cleanup
  // ═══════════════════════════════════════════════════════════════════════════

  var closePtr = Module.findExportByName("libc.so", "close");
  if (closePtr) {
    Interceptor.attach(closePtr, {
      onEnter: function (args) {
        var fd = args[0].toInt32();
        if (sensitiveFds[fd]) delete sensitiveFds[fd];
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // A13+ EXPANSION — process cloning, USB descriptors, Bluetooth HCI, extra props
  // ═══════════════════════════════════════════════════════════════════════════

  // ─── fork / vfork / clone — child processes can evade parent's hooks ─────
  // Not identification per se, but a signal that the app is forking off a
  // helper (e.g. GMS SignInClient spawns a dialog process). Useful to correlate
  // with child-process startup events.
  (function () {
    var forkPtr = Module.findExportByName("libc.so", "fork");
    if (forkPtr) {
      Interceptor.attach(forkPtr, {
        onLeave: function (retval) {
          var pid = retval.toInt32();
          if (pid !== 0 && isNew("PROC_FORK", String(pid))) {
            emit.call(this, "PROC_FORK", "child_pid=" + pid, { pid: pid, syscall: "fork" });
          }
        }
      });
    }
    var vforkPtr = Module.findExportByName("libc.so", "vfork");
    if (vforkPtr) {
      Interceptor.attach(vforkPtr, {
        onLeave: function (retval) {
          var pid = retval.toInt32();
          if (pid !== 0 && isNew("PROC_VFORK", String(pid))) {
            emit.call(this, "PROC_VFORK", "child_pid=" + pid, { pid: pid, syscall: "vfork" });
          }
        }
      });
    }
    var clonePtr = Module.findExportByName("libc.so", "clone");
    if (clonePtr) {
      Interceptor.attach(clonePtr, {
        onEnter: function (args) {
          // clone(fn, stack, flags, arg, ...)
          this.flags = args[2].toInt32 ? args[2].toInt32() : 0;
        },
        onLeave: function (retval) {
          var pid = retval.toInt32();
          if (pid > 0 && isNew("PROC_CLONE", String(pid))) {
            emit.call(this, "PROC_CLONE", "child_pid=" + pid, {
              pid: pid,
              flags: "0x" + (this.flags >>> 0).toString(16),
              syscall: "clone"
            });
          }
        }
      });
    }
  })();

  // ─── USB descriptor snapshot — VID/PID leaks SoC + USB controller vendor ─
  // Scan /sys/bus/usb/devices once; skip if the directory is missing or empty.
  (function () {
    try {
      var openFunc = new NativeFunction(
        Module.findExportByName("libc.so", "open"), "int", ["pointer", "int"]);
      var readFunc = new NativeFunction(
        Module.findExportByName("libc.so", "read"), "int", ["int", "pointer", "int"]);
      var closeFunc = new NativeFunction(
        Module.findExportByName("libc.so", "close"), "int", ["int"]);
      var opendirPtr = Module.findExportByName("libc.so", "opendir");
      var readdirPtr = Module.findExportByName("libc.so", "readdir");
      var closedirPtr = Module.findExportByName("libc.so", "closedir");
      if (!openFunc || !readFunc || !closeFunc || !opendirPtr || !readdirPtr || !closedirPtr) return;

      var opendirFn = new NativeFunction(opendirPtr, "pointer", ["pointer"]);
      var readdirFn = new NativeFunction(readdirPtr, "pointer", ["pointer"]);
      var closedirFn = new NativeFunction(closedirPtr, "int", ["pointer"]);

      var pathBuf = Memory.alloc(256);
      pathBuf.writeUtf8String("/sys/bus/usb/devices");
      var dir = opendirFn(pathBuf);
      if (dir.isNull()) return;

      var devices = [];
      var entry;
      while (!(entry = readdirFn(dir)).isNull()) {
        var dName = entry.add(19).readCString();
        if (!dName || dName.charAt(0) === "." || dName === "usb1") continue;
        // Skip anything that doesn't look like a bus-port notation (e.g. "1-1")
        if (dName.indexOf("-") === -1 && dName.indexOf(":") === -1) continue;

        var vid = null, pid = null;
        try {
          var vidBuf = Memory.alloc(256);
          vidBuf.writeUtf8String("/sys/bus/usb/devices/" + dName + "/idVendor");
          var vfd = openFunc(vidBuf, 0);
          if (vfd > 0) {
            var b = Memory.alloc(16);
            var n = readFunc(vfd, b, 15);
            if (n > 0) vid = b.readCString().trim();
            closeFunc(vfd);
          }
          var pidBuf = Memory.alloc(256);
          pidBuf.writeUtf8String("/sys/bus/usb/devices/" + dName + "/idProduct");
          var pfd = openFunc(pidBuf, 0);
          if (pfd > 0) {
            var b2 = Memory.alloc(16);
            var n2 = readFunc(pfd, b2, 15);
            if (n2 > 0) pid = b2.readCString().trim();
            closeFunc(pfd);
          }
        } catch (e) {}

        if (vid || pid) {
          devices.push({ name: dName, vid: vid, pid: pid });
        }
      }
      closedirFn(dir);

      if (devices.length > 0) {
        send({
          layer: "native",
          type: "USB_DEVICE_SNAPSHOT",
          value: devices.length + " USB devices",
          devices: devices,
          ts: Date.now(),
          backtrace: []
        });
      }
    } catch (e) {}
  })();

  // ─── Bluetooth HCI version — fingerprints BT controller silicon ──────────
  // The libbluetooth / libbluetooth_jni may not be loaded yet; retry on dlopen.
  (function () {
    function scanBtLib() {
      try {
        var btLib = Process.findModuleByName("libbluetooth_jni.so") ||
                    Process.findModuleByName("libbluetooth.so") ||
                    Process.findModuleByName("libbluetooth_qti.so");
        if (!btLib) return false;
        // Just report the library load — version extraction would require
        // running the full HCI initialization which is too invasive here.
        if (isNew("BT_HCI_LIB", btLib.path)) {
          send({
            layer: "native",
            type: "BT_HCI_LIB",
            value: btLib.name,
            path: btLib.path,
            base: btLib.base.toString(),
            size: btLib.size,
            ts: Date.now(),
            backtrace: []
          });
        }
        return true;
      } catch (e) { return false; }
    }
    if (!scanBtLib()) {
      // Hook dlopen to catch late load
      var dlopenPtr = Module.findExportByName(null, "dlopen");
      if (dlopenPtr) {
        var origDl = Interceptor.attach(dlopenPtr, {
          onEnter: function (args) {
            try {
              var name = readCStr(args[0]);
              if (name && (name.indexOf("libbluetooth") !== -1 || name.indexOf("bt_") !== -1)) {
                this._btLoad = name;
              }
            } catch (e) {}
          },
          onLeave: function () {
            if (this._btLoad) scanBtLib();
          }
        });
      }
    }
  })();

  // ─── AAssetManager / bridge_observables — mirror of OmniShield Valdi hook ─
  // Snapchat loads a compiled JS bundle from its APK assets; logging the path
  // helps correlate Snap's feature-flag state with identity-read bursts.
  (function () {
    var aamOpenPtr = Module.findExportByName("libandroid.so", "AAssetManager_open");
    if (aamOpenPtr) {
      Interceptor.attach(aamOpenPtr, {
        onEnter: function (args) {
          try {
            var path = readCStr(args[1]);
            if (path && path.indexOf("bridge_observables") !== -1) {
              emit.call(this, "AASSET_OPEN", path, { lib: "libandroid.so" });
            }
          } catch (e) {}
        }
      });
    }
  })();

  // ─── getauxval — reveals process' real UID/GID via AT_UID/AT_GID ─────────
  (function () {
    var auxvalPtr = Module.findExportByName("libc.so", "getauxval");
    if (auxvalPtr) {
      Interceptor.attach(auxvalPtr, {
        onEnter: function (args) { this.type = args[0].toInt32(); },
        onLeave: function (retval) {
          // AT_UID=11, AT_EUID=12, AT_GID=13, AT_EGID=14, AT_SECURE=23, AT_HWCAP=16
          if (this.type === 11 || this.type === 12 || this.type === 13 ||
              this.type === 14 || this.type === 23) {
            var key = "AUXVAL_" + this.type;
            if (isNew(key, String(retval.toInt32()))) {
              emit.call(this, "GETAUXVAL", "type=" + this.type + " val=" + retval.toInt32(), {
                type: this.type, value: retval.toInt32()
              });
            }
          }
        }
      });
    }
  })();

  // ─── gettimeofday / clock_gettime — boot time fingerprints ───────────────
  // Not directly but CLOCK_BOOTTIME + process-start offset creates a device
  // boot signature; this is a passive observation (no dedup — only log once
  // per process start via isNew).
  (function () {
    var cgtPtr = Module.findExportByName("libc.so", "clock_gettime");
    if (cgtPtr) {
      var logged = false;
      Interceptor.attach(cgtPtr, {
        onEnter: function (args) {
          if (logged) return;
          var clockId = args[0].toInt32();
          // CLOCK_BOOTTIME=7, CLOCK_MONOTONIC=1, CLOCK_REALTIME=0
          if (clockId === 7) {
            this._logBoot = true;
          }
        },
        onLeave: function () {
          if (this._logBoot && !logged) {
            logged = true;
            emit.call(this, "CLOCK_BOOTTIME_QUERY", "first_query", { clockId: 7 });
          }
        }
      });
    }
  })();

  // ═══════════════════════════════════════════════════════════════════════════
  // DONE
  // ═══════════════════════════════════════════════════════════════════════════

  send({ layer: "native", type: "__INIT__", value: "Layer 2 (Native v3 / OmniShield v1.52.2) hooks loaded — file I/O, stat, access, readlink, uname, sysinfo, ioctl, getifaddrs, recvmsg, properties(130+keys incl. v1.52.2 additions: 6 serial variants [ro.serialno/ro.boot.serialno/ro.vendor.product.serial/persist.sys.serialno/vendor.serialno/ril.serialnumber], 7 fingerprint variants [+ro.bootimage.build.fingerprint], 7 build-id partitions [ro.build.id +6 siblings], ro.build.tags/type retail pair, MCC/MNC gsm.* + iso-country), EGL, GL, Vulkan, dl_iterate_phdr, mmap/mprotect, connect, prctl, ptrace, opendir/readdir, socket, kill, fork/vfork/clone, USB VID/PID snapshot, BT HCI lib, AAssetManager_open, getauxval, clock_gettime(BOOTTIME), APEX path filters", ts: Date.now(), backtrace: [] });

})();
