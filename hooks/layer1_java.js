/**
 * Layer 1 — Java Framework Hooks (Expanded)
 * Intercepts ALL Android Java APIs that expose device identity, hardware
 * fingerprint, and user data — aligned with OmniShield's hook surface.
 *
 * Categories:
 *   BUILD         — Build.*, Build.VERSION.* static fields (36+ fields)
 *   TELEPHONY     — IMEI, IMSI, ICCID, phone number, carrier, country ISO,
 *                   cell info, SIM state, network type, MEID
 *   SETTINGS      — Settings.Secure (android_id, accessibility, bluetooth),
 *                   Settings.Global (device_name)
 *   LOCATION      — lat/lon/alt/accuracy/speed/bearing/time/mock
 *   SENSOR        — full sensor enumeration + properties
 *   NETWORK       — ConnectivityManager, WiFi, Bluetooth MACs
 *   MEDIA_DRM     — Widevine device ID, vendor, version
 *   MEDIA_CODEC   — codec enumeration (SoC fingerprint)
 *   CURSOR_WINDOW — GSF ID via content provider
 *   DISPLAY       — DisplayMetrics density/resolution
 *   TIMEZONE      — TimeZone.getDefault, Locale.getDefault
 *   SYSTEM_PROP   — System.getProperty (http.agent, os.version, etc.)
 *   WEBVIEW       — WebView user agent
 *   ADVERTISING   — GAID via AdvertisingIdClient
 *   CRYPTO        — KeyStore, Cipher, MessageDigest, Valdi
 *   SSL           — cert pinning bypass
 *   PRIVACY       — clipboard, installed apps, accounts, contacts
 */

Java.perform(function () {

  // ─── Dedup cache ──────────────────────────────────────────────────────────

  var reported = {};
  function isNew(type, value) {
    var key = type + ":" + (value || "");
    if (reported[key]) return false;
    reported[key] = true;
    return true;
  }

  // ─── Temporal correlation — digest burst → Cipher.doFinal ──────────────────

  var digestWindow = [];
  var DIGEST_WINDOW_MS = 15000;

  function digestAccumPush(entry) {
    var now = Date.now();
    digestWindow = digestWindow.filter(function (e) { return now - e.ts < DIGEST_WINDOW_MS; });
    digestWindow.push(entry);
  }

  function digestAccumFlush() {
    var snap = digestWindow.slice();
    digestWindow = [];
    return snap;
  }

  // Alert types warrant a full (slower) stack trace
  var ALERT_TYPES = new Set([
    "IMEI", "IMSI", "PHONE_NUMBER", "SIM_SERIAL",
    "ANDROID_ID", "ADVERTISING_ID", "DEVICE_SERIAL",
    "LOCATION", "ACCOUNTS", "GAID", "GSF_ID",
    "MEDIA_DRM_DEVICE_ID", "MEID",
    // A13+ additions
    "CONTEXT_DEVICE_ID", "SUB_PHONE_NUMBER", "DEVICE_PHONE_NUMBER_SETTING",
    "WIDEVINE_PROVISIONING_ID", "WIDEVINE_DEVICE_UNIQUE_ID",
    "UWB_CHIP_ID", "NFC_ID", "BT_BLE_ADDRESS",
    "USER_SERIAL_NUMBER", "USER_CREATION_TIME",
    "STORAGE_UUID", "INSTALLER_PACKAGE", "FIRST_INSTALL_TIME",
    "PARCEL_READ_STRING8", "PARCEL_READ_STRING16",
    "TELEPHONY_HAL_VERSION", "UICC_CARDS_INFO",
    "TYPE_ALLOCATION_CODE", "MANUFACTURER_CODE",
    "HEALTH_CONNECT",
    // Snap-specific cohorts (from forensic report v13.88.1.0)
    "SNAP_DEVICE_ID_COHORT", "SNAP_ATTESTATION_TYPE",
    "SNAP_ARGOS_CLIENT", "SNAP_CLIENT_ATTESTATION_INTERCEPTOR",
    "SNAP_VENDOR_ATTESTATION", "SNAP_TIVS_DEVICEDATA",
    "SNAP_VALIS_DEVICEDATA",
    // Keystore attestation (cert-chain and challenge binding)
    "KEYSTORE_ATTESTATION_CHALLENGE", "KEYSTORE_CERT_CHAIN",
    "KEYSTORE_ATTESTATION_KEY_SPEC"
  ]);

  var SKIP_PREFIXES = [
    "java.lang", "java.util", "java.io", "java.reflect",
    "sun.reflect", "dalvik.", "com.android.internal",
    "android.os.Handler", "android.app.ActivityThread",
    "com.frida"
  ];

  // filteredStack(): DISABLED for JNI-global-ref-safety.
  //
  // Prior implementation: Java.use("java.lang.Thread").currentThread().getStackTrace()
  // plus per-frame toString(). Each call leaked ~7 JNI global refs (1 Thread +
  // up to 6 StackTraceElement refs) because Frida's Java bridge retains those
  // refs until JS GC runs, which is far slower than emit() frequency under
  // Snap's active load. Accumulated to 51,200 refs (JNI table max) in ~40 s →
  // SIGABRT "global reference table overflow". See tombstone_13/_14.
  //
  // Replaced with a no-op; the method/arguments passed to emit() already
  // identify the call site. If stack context is ever needed again, implement
  // via native Thread.backtrace() (no Java refs), not the Java API.
  function filteredStack() {
    return [];
  }

  function emit(type, value, extra) {
    var stack = ALERT_TYPES.has(type) ? filteredStack() : [];
    var payload = {
      layer: "java",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      caller: stack.length > 0 ? stack[0] : type,
      stack: stack,
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    send(payload);
  }

  function hookMethod(className, methodName, overloadArgs, handler) {
    try {
      var cls = Java.use(className);
      var method = overloadArgs
        ? cls[methodName].overload.apply(cls[methodName], overloadArgs)
        : cls[methodName];
      method.implementation = handler;
    } catch (e) {
      // Class or method not available on this device/API level — skip silently
    }
  }

  // Safe field reader
  function readField(cls, fieldName) {
    try { return cls[fieldName] ? String(cls[fieldName].value) : null; } catch (e) { return null; }
  }

  // ─── System Property Cache (post-OmniShield values) ─────────────────────
  // NOTE: OmniShield hooks __system_property_get via DobbyHook inline.
  // These values are post-spoof. Useful for detecting discrepancies where
  // Java API returns empty/wrong but sysprop has a coherent value (indicates
  // OmniShield bug at Java level, not real vs spoofed).
  var _syspropCache = {};
  (function buildSyspropCache() {
    try {
      var ptr = Module.findExportByName("libc.so", "__system_property_get");
      if (!ptr) return;
      var propGet = new NativeFunction(ptr, "int", ["pointer", "pointer"]);
      var nBuf = Memory.alloc(256);
      var vBuf = Memory.alloc(256);
      var keys = [
        "gsm.sim.operator.numeric", "gsm.sim.operator.iso-country",
        "gsm.sim.operator.alpha", "gsm.operator.numeric",
        "gsm.operator.iso-country", "gsm.operator.alpha",
        "gsm.network.type", "gsm.sim.state",
        "gsm.version.baseband", "ro.telephony.default_network"
      ];
      for (var i = 0; i < keys.length; i++) {
        try {
          nBuf.writeUtf8String(keys[i]);
          vBuf.writeByteArray(new ArrayBuffer(256));
          propGet(nBuf, vBuf);
          var val = vBuf.readCString();
          if (val && val.length > 0) _syspropCache[keys[i]] = val;
        } catch (e) {}
      }
    } catch (e) {}
  })();

  function getSysprop(key) {
    return _syspropCache[key] || null;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BUILD FIELDS — 36+ static fields from android.os.Build / Build.VERSION
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var Build = Java.use("android.os.Build");
    var buildFields = [
      "SERIAL", "FINGERPRINT", "MODEL", "MANUFACTURER", "BRAND",
      "DEVICE", "PRODUCT", "HARDWARE", "BOARD", "BOOTLOADER",
      "DISPLAY", "HOST", "USER", "TAGS", "TYPE", "ID",
      "RADIO", "TIME"
    ];
    for (var i = 0; i < buildFields.length; i++) {
      var val = readField(Build, buildFields[i]);
      if (val !== null) {
        emit("BUILD", val, { field: "Build." + buildFields[i] });
      }
    }
  } catch (e) {}

  try {
    var BuildVersion = Java.use("android.os.Build$VERSION");
    var versionFields = [
      "RELEASE", "SDK_INT", "SECURITY_PATCH", "INCREMENTAL",
      "CODENAME", "BASE_OS", "PREVIEW_SDK_INT"
    ];
    for (var i = 0; i < versionFields.length; i++) {
      var val = readField(BuildVersion, versionFields[i]);
      if (val !== null) {
        emit("BUILD_VERSION", val, { field: "Build.VERSION." + versionFields[i] });
      }
    }
  } catch (e) {}

  hookMethod("android.os.Build", "getSerial", [], function () {
    var v = this.getSerial();
    emit("DEVICE_SERIAL", v, { method: "Build.getSerial()" });
    return v;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // TELEPHONY — full TelephonyManager coverage
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.telephony.TelephonyManager", "getImei", [], function () {
    var v = this.getImei();
    if (isNew("IMEI", v)) emit("IMEI", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getImei", ["int"], function (slot) {
    var v = this.getImei(slot);
    if (isNew("IMEI", v)) emit("IMEI", v, { slot: slot });
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getDeviceId", [], function () {
    var v = this.getDeviceId();
    if (isNew("IMEI", v)) emit("IMEI", v, { method: "getDeviceId" });
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getDeviceId", ["int"], function (slot) {
    var v = this.getDeviceId(slot);
    if (isNew("IMEI", v)) emit("IMEI", v, { method: "getDeviceId", slot: slot });
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getMeid", [], function () {
    var v = this.getMeid();
    if (isNew("MEID", v)) emit("MEID", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getMeid", ["int"], function (slot) {
    var v = this.getMeid(slot);
    if (isNew("MEID", v)) emit("MEID", v, { slot: slot });
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSubscriberId", [], function () {
    var v = this.getSubscriberId();
    if (isNew("IMSI", v)) emit("IMSI", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getLine1Number", [], function () {
    var v = this.getLine1Number();
    if (isNew("PHONE_NUMBER", v)) {
      var extra = {};
      if (v && v.length <= 3 && /^[a-zA-Z]{2,3}$/.test(v)) {
        extra.anomaly = "LIKELY_COUNTRY_ISO";
        extra.anomalyReason = "Value '" + v + "' looks like country ISO, not phone number";
      }
      if ((!v || v === "") && getSysprop("gsm.sim.state") === "READY") {
        extra.anomaly = "POSSIBLY_HIDDEN";
        extra.anomalyReason = "Empty phone number but gsm.sim.state=READY";
      }
      emit("PHONE_NUMBER", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimSerialNumber", [], function () {
    var v = this.getSimSerialNumber();
    if (isNew("SIM_SERIAL", v)) emit("SIM_SERIAL", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimOperatorName", [], function () {
    var v = this.getSimOperatorName();
    if (isNew("SIM_OPERATOR_NAME", v)) {
      var extra = {};
      var sp = getSysprop("gsm.sim.operator.alpha");
      if ((!v || v === "") && sp) {
        extra.anomaly = "JAVA_EMPTY"; extra.anomalyReason = "Java empty, sysprop=" + sp; extra.syspropValue = sp;
      } else if (v && sp && v !== sp) {
        extra.anomaly = "MISMATCH"; extra.anomalyReason = "Java='" + v + "' sysprop='" + sp + "'"; extra.syspropValue = sp;
      }
      emit("SIM_OPERATOR_NAME", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimOperator", [], function () {
    var v = this.getSimOperator();
    if (isNew("SIM_OPERATOR_NUMERIC", v)) {
      var extra = { field: "MCC+MNC" };
      var sp = getSysprop("gsm.sim.operator.numeric");
      if ((!v || v === "") && sp) {
        extra.anomaly = "JAVA_EMPTY"; extra.anomalyReason = "Java empty, sysprop=" + sp; extra.syspropValue = sp;
      } else if (v && sp && v !== sp) {
        extra.anomaly = "MISMATCH"; extra.anomalyReason = "Java='" + v + "' sysprop='" + sp + "'"; extra.syspropValue = sp;
      }
      emit("SIM_OPERATOR_NUMERIC", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getNetworkOperatorName", [], function () {
    var v = this.getNetworkOperatorName();
    if (isNew("NETWORK_OPERATOR_NAME", v)) {
      var extra = {};
      var sp = getSysprop("gsm.operator.alpha");
      if ((!v || v === "") && sp) {
        extra.anomaly = "JAVA_EMPTY"; extra.anomalyReason = "Java empty, sysprop=" + sp; extra.syspropValue = sp;
      } else if (v && sp && v !== sp) {
        extra.anomaly = "MISMATCH"; extra.anomalyReason = "Java='" + v + "' sysprop='" + sp + "'"; extra.syspropValue = sp;
      }
      emit("NETWORK_OPERATOR_NAME", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getNetworkOperator", [], function () {
    var v = this.getNetworkOperator();
    if (isNew("NETWORK_OPERATOR_NUMERIC", v)) {
      var extra = { field: "MCC+MNC" };
      var sp = getSysprop("gsm.operator.numeric");
      if ((!v || v === "") && sp) {
        extra.anomaly = "JAVA_EMPTY"; extra.anomalyReason = "Java empty, sysprop=" + sp; extra.syspropValue = sp;
      } else if (v && sp && v !== sp) {
        extra.anomaly = "MISMATCH"; extra.anomalyReason = "Java='" + v + "' sysprop='" + sp + "'"; extra.syspropValue = sp;
      }
      emit("NETWORK_OPERATOR_NUMERIC", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getNetworkCountryIso", [], function () {
    var v = this.getNetworkCountryIso();
    if (isNew("NETWORK_COUNTRY_ISO", v)) {
      var extra = {};
      var sp = getSysprop("gsm.operator.iso-country");
      if ((!v || v === "") && sp) {
        extra.anomaly = "JAVA_EMPTY"; extra.anomalyReason = "Java empty, sysprop=" + sp; extra.syspropValue = sp;
      } else if (v && sp && v !== sp) {
        extra.anomaly = "MISMATCH"; extra.anomalyReason = "Java='" + v + "' sysprop='" + sp + "'"; extra.syspropValue = sp;
      }
      emit("NETWORK_COUNTRY_ISO", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimCountryIso", [], function () {
    var v = this.getSimCountryIso();
    if (isNew("SIM_COUNTRY_ISO", v)) {
      var extra = {};
      var sp = getSysprop("gsm.sim.operator.iso-country");
      if ((!v || v === "") && sp) {
        extra.anomaly = "JAVA_EMPTY"; extra.anomalyReason = "Java empty, sysprop=" + sp; extra.syspropValue = sp;
      } else if (v && sp && v !== sp) {
        extra.anomaly = "MISMATCH"; extra.anomalyReason = "Java='" + v + "' sysprop='" + sp + "'"; extra.syspropValue = sp;
      }
      emit("SIM_COUNTRY_ISO", v, extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getNetworkType", [], function () {
    var v = this.getNetworkType();
    var names = { 0: "UNKNOWN", 1: "GPRS", 2: "EDGE", 3: "UMTS", 4: "CDMA", 5: "EVDO_0",
      6: "EVDO_A", 7: "1xRTT", 8: "HSDPA", 9: "HSUPA", 10: "HSPA", 13: "LTE", 20: "NR" };
    if (isNew("NETWORK_TYPE", v)) emit("NETWORK_TYPE", names[v] || String(v), { raw: v });
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getDataNetworkType", [], function () {
    var v = this.getDataNetworkType();
    if (isNew("DATA_NETWORK_TYPE", v)) {
      var extra = { raw: v };
      if (v === 0) {
        var sp = getSysprop("gsm.network.type");
        if (sp && sp !== "0" && sp !== "") {
          extra.anomaly = "JAVA_ZERO"; extra.anomalyReason = "Java returns UNKNOWN(0), sysprop gsm.network.type=" + sp; extra.syspropValue = sp;
        }
      }
      emit("DATA_NETWORK_TYPE", String(v), extra);
    }
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getPhoneType", [], function () {
    var v = this.getPhoneType();
    var names = { 0: "NONE", 1: "GSM", 2: "CDMA", 3: "SIP" };
    if (isNew("PHONE_TYPE", v)) emit("PHONE_TYPE", names[v] || String(v));
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimState", [], function () {
    var v = this.getSimState();
    var names = { 0: "UNKNOWN", 1: "ABSENT", 2: "PIN_REQUIRED", 3: "PUK_REQUIRED",
      4: "NETWORK_LOCKED", 5: "READY", 6: "NOT_READY", 7: "DISABLED" };
    if (isNew("SIM_STATE", v)) emit("SIM_STATE", names[v] || String(v));
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "hasIccCard", [], function () {
    var v = this.hasIccCard();
    if (isNew("HAS_ICC_CARD", v)) emit("HAS_ICC_CARD", String(v));
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "isNetworkRoaming", [], function () {
    var v = this.isNetworkRoaming();
    if (isNew("IS_ROAMING", v)) emit("IS_ROAMING", String(v));
    return v;
  });

  // Cell tower info — OmniShield returns empty lists
  hookMethod("android.telephony.TelephonyManager", "getAllCellInfo", [], function () {
    var list = this.getAllCellInfo();
    var count = list !== null ? list.size() : 0;
    if (isNew("CELL_INFO", count)) {
      var details = [];
      if (list !== null) {
        for (var i = 0; i < Math.min(count, 5); i++) {
          try { details.push(list.get(i).toString().substring(0, 100)); } catch (e) {}
        }
      }
      emit("CELL_INFO", count + " cells", { count: count, first5: details.join(" | ") });
    }
    return list;
  });

  hookMethod("android.telephony.TelephonyManager", "getCellLocation", [], function () {
    var loc = this.getCellLocation();
    emit("CELL_LOCATION", loc !== null ? loc.toString() : "null");
    return loc;
  });

  hookMethod("android.telephony.TelephonyManager", "getServiceState", [], function () {
    var ss = this.getServiceState();
    if (ss !== null) {
      emit("SERVICE_STATE", ss.toString().substring(0, 200));
    } else {
      emit("SERVICE_STATE", "null");
    }
    return ss;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SETTINGS.SECURE — android_id + accessibility + bluetooth
  // ═══════════════════════════════════════════════════════════════════════════

  var SETTINGS_SECURE_KEYS = [
    "android_id", "bluetooth_address", "bluetooth_name",
    "enabled_accessibility_services", "accessibility_enabled",
    "touch_exploration_enabled", "speak_password",
    "lock_screen_lock_after_timeout", "default_input_method"
  ];

  hookMethod(
    "android.provider.Settings$Secure",
    "getString",
    ["android.content.ContentResolver", "java.lang.String"],
    function (cr, name) {
      var v = this.getString(cr, name);
      if (name) {
        var lower = name.toLowerCase();
        for (var i = 0; i < SETTINGS_SECURE_KEYS.length; i++) {
          if (lower === SETTINGS_SECURE_KEYS[i]) {
            if (isNew("SETTINGS_SECURE", name + "=" + v)) {
              emit("SETTINGS_SECURE", v, { key: name });
            }
            break;
          }
        }
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // SETTINGS.GLOBAL — device_name
  // ═══════════════════════════════════════════════════════════════════════════

  var SETTINGS_GLOBAL_KEYS = [
    "device_name", "airplane_mode_on", "mobile_data",
    "wifi_on", "bluetooth_on", "development_settings_enabled",
    "adb_enabled", "usb_mass_storage_enabled"
  ];

  hookMethod(
    "android.provider.Settings$Global",
    "getString",
    ["android.content.ContentResolver", "java.lang.String"],
    function (cr, name) {
      var v = this.getString(cr, name);
      if (name) {
        var lower = name.toLowerCase();
        for (var i = 0; i < SETTINGS_GLOBAL_KEYS.length; i++) {
          if (lower === SETTINGS_GLOBAL_KEYS[i]) {
            if (isNew("SETTINGS_GLOBAL", name + "=" + v)) {
              emit("SETTINGS_GLOBAL", v, { key: name });
            }
            break;
          }
        }
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // LOCATION — full Location object fields
  // ═══════════════════════════════════════════════════════════════════════════

  // Capture all fields when a Location object is returned
  function emitLocationFull(loc, source) {
    if (loc === null) {
      emit("LOCATION", "null", { source: source });
      return;
    }
    try {
      emit("LOCATION", loc.getLatitude() + "," + loc.getLongitude(), {
        source: source,
        latitude: loc.getLatitude(),
        longitude: loc.getLongitude(),
        altitude: loc.getAltitude(),
        accuracy: loc.getAccuracy(),
        speed: loc.getSpeed(),
        bearing: loc.getBearing(),
        time: loc.getTime(),
        provider: loc.getProvider(),
        isFromMockProvider: loc.isFromMockProvider()
      });
    } catch (e) {
      emit("LOCATION", "(error reading)", { source: source, error: e.toString() });
    }
  }

  hookMethod(
    "android.location.LocationManager",
    "getLastKnownLocation",
    ["java.lang.String"],
    function (provider) {
      var loc = this.getLastKnownLocation(provider);
      emitLocationFull(loc, "getLastKnownLocation(" + provider + ")");
      return loc;
    }
  );

  hookMethod(
    "android.location.LocationManager",
    "requestLocationUpdates",
    ["java.lang.String", "long", "float", "android.location.LocationListener"],
    function (provider, minTime, minDist, listener) {
      emit("LOCATION_REQUEST", provider, {
        minTimeMs: minTime,
        minDistMeters: minDist,
        method: "requestLocationUpdates"
      });
      return this.requestLocationUpdates(provider, minTime, minDist, listener);
    }
  );

  // Hook Location getter methods individually for passive interception
  var locationGetters = [
    { method: "getLatitude",  type: "LOCATION_LAT" },
    { method: "getLongitude", type: "LOCATION_LON" },
    { method: "getAltitude",  type: "LOCATION_ALT" },
    { method: "getAccuracy",  type: "LOCATION_ACCURACY" },
    { method: "getSpeed",     type: "LOCATION_SPEED" },
    { method: "getBearing",   type: "LOCATION_BEARING" },
    { method: "getProvider",  type: "LOCATION_PROVIDER" }
  ];

  for (var lg = 0; lg < locationGetters.length; lg++) {
    (function(getter) {
      hookMethod("android.location.Location", getter.method, [], function () {
        var v = this[getter.method]();
        if (isNew(getter.type, v)) emit(getter.type, String(v), { method: getter.method });
        return v;
      });
    })(locationGetters[lg]);
  }

  hookMethod("android.location.Location", "isFromMockProvider", [], function () {
    var v = this.isFromMockProvider();
    if (isNew("LOCATION_MOCK", v)) emit("LOCATION_MOCK", String(v));
    return v;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SENSORS — full enumeration + per-sensor properties
  // ═══════════════════════════════════════════════════════════════════════════

  // Intercept getSensorList to capture full sensor inventory
  hookMethod(
    "android.hardware.SensorManager",
    "getSensorList",
    ["int"],
    function (type) {
      var list = this.getSensorList(type);
      if (list !== null && list.size() > 0) {
        for (var i = 0; i < list.size(); i++) {
          try {
            var s = list.get(i);
            var key = "SENSOR_LIST:" + s.getType() + ":" + s.getName();
            if (isNew("SENSOR_LIST", key)) {
              emit("SENSOR_LIST", s.getName(), {
                type: s.getType(),
                vendor: s.getVendor(),
                version: s.getVersion(),
                maxRange: s.getMaximumRange(),
                resolution: s.getResolution(),
                power: s.getPower(),
                minDelay: s.getMinDelay(),
                stringType: s.getStringType()
              });
            }
          } catch (e) {}
        }
      }
      return list;
    }
  );

  hookMethod(
    "android.hardware.SensorManager",
    "registerListener",
    ["android.hardware.SensorEventListener", "android.hardware.Sensor", "int"],
    function (listener, sensor, rate) {
      if (sensor !== null) {
        var key = sensor.getType() + ":" + sensor.getName();
        if (isNew("SENSOR_REGISTER", key)) {
          emit("SENSOR_REGISTER", sensor.getName(), {
            type: sensor.getType(),
            vendor: sensor.getVendor(),
            maxRange: sensor.getMaximumRange(),
            resolution: sensor.getResolution(),
            rate: rate
          });
        }
      }
      return this.registerListener(listener, sensor, rate);
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // NETWORK — ConnectivityManager + WiFi
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.net.ConnectivityManager", "getActiveNetworkInfo", [], function () {
    var info = this.getActiveNetworkInfo();
    if (info !== null) {
      if (isNew("NETWORK_INFO", "active")) {
        emit("NETWORK_INFO", info.toString(), {
          type: info.getType(),
          typeName: info.getTypeName(),
          subtype: info.getSubtype(),
          subtypeName: info.getSubtypeName(),
          isConnected: info.isConnected(),
          isRoaming: info.isRoaming(),
          extraInfo: info.getExtraInfo()
        });
      }
    }
    return info;
  });

  // WiFi MAC
  hookMethod("android.net.wifi.WifiManager", "getConnectionInfo", [], function () {
    var info = this.getConnectionInfo();
    if (info !== null) {
      try {
        var mac = info.getMacAddress();
        var ssid = info.getSSID();
        var bssid = info.getBSSID();
        if (isNew("WIFI_INFO", mac)) {
          emit("WIFI_INFO", mac, {
            mac: mac,
            ssid: ssid,
            bssid: bssid,
            rssi: info.getRssi(),
            linkSpeed: info.getLinkSpeed()
          });
        }
      } catch (e) {}
    }
    return info;
  });

  // Bluetooth MAC
  hookMethod("android.bluetooth.BluetoothAdapter", "getAddress", [], function () {
    var v = this.getAddress();
    if (isNew("MAC_BLUETOOTH", v)) emit("MAC_BLUETOOTH", v);
    return v;
  });

  hookMethod("android.bluetooth.BluetoothAdapter", "getName", [], function () {
    var v = this.getName();
    if (isNew("BLUETOOTH_NAME", v)) emit("BLUETOOTH_NAME", v);
    return v;
  });

  // NetworkInterface (hardware MAC)
  hookMethod("java.net.NetworkInterface", "getHardwareAddress", [], function () {
    var bytes = this.getHardwareAddress();
    if (bytes !== null) {
      var hex = [];
      for (var i = 0; i < bytes.length; i++) {
        hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
      }
      var mac = hex.join(":");
      if (isNew("MAC_NETWORK_IFACE", this.getName() + "=" + mac)) {
        emit("MAC_NETWORK_IFACE", mac, { iface: this.getName() });
      }
    }
    return bytes;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // MEDIA DRM — Widevine device ID + properties
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.media.MediaDrm",
    "getPropertyByteArray",
    ["java.lang.String"],
    function (name) {
      var result = this.getPropertyByteArray(name);
      if (result !== null) {
        var hex = [];
        try {
          var arr = Java.array("byte", result);
          for (var i = 0; i < Math.min(arr.length, 32); i++) {
            hex.push(("0" + (arr[i] & 0xFF).toString(16)).slice(-2));
          }
        } catch (e) {}
        if (isNew("MEDIA_DRM_BYTES", name)) {
          emit("MEDIA_DRM_BYTES", hex.join(""), {
            property: name,
            len: result.length,
            isDeviceId: name === "deviceUniqueId" || name === "device_unique_id"
          });
        }
      }
      return result;
    }
  );

  hookMethod(
    "android.media.MediaDrm",
    "getPropertyString",
    ["java.lang.String"],
    function (name) {
      var v = this.getPropertyString(name);
      if (isNew("MEDIA_DRM_STRING", name + "=" + v)) {
        emit("MEDIA_DRM_STRING", v, { property: name });
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // MEDIA CODEC LIST — SoC codec name fingerprint
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.media.MediaCodecList", "getCodecInfoAt", ["int"], function (index) {
    var info = this.getCodecInfoAt(index);
    if (info !== null) {
      var name = info.getName();
      if (isNew("CODEC_INFO", name)) {
        emit("CODEC_INFO", name, {
          index: index,
          isEncoder: info.isEncoder()
        });
      }
    }
    return info;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // CURSOR WINDOW — GSF ID via content provider
  // ═══════════════════════════════════════════════════════════════════════════

  // CursorWindow.getString — captures GSF ID string reads
  hookMethod(
    "android.database.CursorWindow",
    "getString",
    ["int", "int"],
    function (row, col) {
      var v = this.getString(row, col);
      // GSF ID is a 16-19 digit numeric string
      if (v !== null && /^\d{14,19}$/.test(v)) {
        if (isNew("CURSOR_WINDOW_GSF", v)) {
          emit("CURSOR_WINDOW_GSF", v, {
            row: row, col: col,
            suspect: "GSF_ID (numeric 14-19 digits)"
          });
        }
      }
      // Also catch UUID-format strings (GAID, AppSetID, OAID)
      if (v !== null && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) {
        if (isNew("CURSOR_WINDOW_UUID", v)) {
          emit("CURSOR_WINDOW_UUID", v, {
            row: row, col: col,
            suspect: "UUID (GAID/AppSetID/OAID)"
          });
        }
      }
      return v;
    }
  );

  hookMethod(
    "android.database.CursorWindow",
    "getLong",
    ["int", "int"],
    function (row, col) {
      var v = this.getLong(row, col);
      // GSF ID as int64 is > 10^15
      if (v > 1e15 && v < 1e19) {
        var isIntMax = (String(v) === "9223372036854775807");
        var tag = isIntMax ? "CURSOR_WINDOW_GSF_LONG_OVERFLOW" : "CURSOR_WINDOW_GSF_LONG";
        if (isNew(tag, v)) {
          emit(tag, String(v), {
            row: row, col: col,
            suspect: isIntMax ? "INT64_MAX (strtoll overflow — check if OmniShield hook fired)" : "GSF_ID_LONG (spoofed or real)"
          });
        }
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // DISPLAY METRICS — density, resolution
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var Resources = Java.use("android.content.res.Resources");
    var dm = Resources.getSystem().getDisplayMetrics();
    if (dm !== null) {
      emit("DISPLAY_METRICS", dm.densityDpi.value + "dpi", {
        densityDpi: dm.densityDpi.value,
        density: dm.density.value,
        widthPixels: dm.widthPixels.value,
        heightPixels: dm.heightPixels.value,
        xdpi: dm.xdpi.value,
        ydpi: dm.ydpi.value,
        scaledDensity: dm.scaledDensity.value
      });
    }
  } catch (e) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // TIMEZONE & LOCALE — cached Java values
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var TimeZone = Java.use("java.util.TimeZone");
    var tz = TimeZone.getDefault();
    if (tz !== null) {
      emit("TIMEZONE", tz.getID(), { displayName: tz.getDisplayName() });
    }
  } catch (e) {}

  try {
    var Locale = Java.use("java.util.Locale");
    var loc = Locale.getDefault();
    if (loc !== null) {
      emit("LOCALE", loc.toString(), {
        language: loc.getLanguage(),
        country: loc.getCountry(),
        displayName: loc.getDisplayName()
      });
    }
  } catch (e) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // SYSTEM.GETPROPERTY — http.agent, os.version, user.timezone, etc.
  // ═══════════════════════════════════════════════════════════════════════════

  var SYSTEM_PROPS_TO_CAPTURE = [
    "http.agent", "os.version", "os.arch", "os.name",
    "user.timezone", "user.country", "user.language", "user.region",
    "java.vm.version", "persist.sys.timezone"
  ];

  try {
    var System = Java.use("java.lang.System");
    for (var sp = 0; sp < SYSTEM_PROPS_TO_CAPTURE.length; sp++) {
      try {
        var val = System.getProperty(SYSTEM_PROPS_TO_CAPTURE[sp]);
        if (val !== null) {
          emit("SYSTEM_PROPERTY_JAVA", val, { key: SYSTEM_PROPS_TO_CAPTURE[sp] });
        }
      } catch (e) {}
    }
  } catch (e) {}

  // Also hook the method for runtime calls
  hookMethod("java.lang.System", "getProperty", ["java.lang.String"], function (key) {
    var v = this.getProperty(key);
    for (var i = 0; i < SYSTEM_PROPS_TO_CAPTURE.length; i++) {
      if (key === SYSTEM_PROPS_TO_CAPTURE[i]) {
        if (isNew("SYSTEM_PROPERTY_JAVA_CALL", key + "=" + v)) {
          emit("SYSTEM_PROPERTY_JAVA_CALL", v, { key: key });
        }
        break;
      }
    }
    return v;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WEBVIEW — user agent string
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.webkit.WebSettings",
    "getUserAgentString",
    [],
    function () {
      var v = this.getUserAgentString();
      if (isNew("WEBVIEW_UA", v)) emit("WEBVIEW_UA", v);
      return v;
    }
  );

  hookMethod(
    "android.webkit.WebSettings",
    "setUserAgentString",
    ["java.lang.String"],
    function (ua) {
      if (isNew("WEBVIEW_UA_SET", ua)) emit("WEBVIEW_UA_SET", ua);
      return this.setUserAgentString(ua);
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // GOOGLE ADVERTISING ID
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "com.google.android.gms.ads.identifier.AdvertisingIdClient",
    "getAdvertisingIdInfo",
    ["android.content.Context"],
    function (ctx) {
      var info = this.getAdvertisingIdInfo(ctx);
      if (info !== null) {
        var gaid = info.getId();
        if (isNew("GAID", gaid)) {
          emit("GAID", gaid, {
            limitAdTracking: info.isLimitAdTrackingEnabled(),
            method: "AdvertisingIdClient.getAdvertisingIdInfo"
          });
        }
      }
      return info;
    }
  );

  // Also hook the Info object's getId() directly
  hookMethod(
    "com.google.android.gms.ads.identifier.AdvertisingIdClient$Info",
    "getId",
    [],
    function () {
      var v = this.getId();
      if (isNew("GAID_DIRECT", v)) {
        emit("GAID", v, { method: "AdvertisingIdClient.Info.getId" });
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // BATTERY — BatteryManager
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.os.BatteryManager",
    "getIntProperty",
    ["int"],
    function (id) {
      var v = this.getIntProperty(id);
      var names = { 1: "STATUS", 2: "HEALTH", 4: "TEMPERATURE", 5: "VOLTAGE" };
      var name = names[id];
      if (name && isNew("BATTERY", name + "=" + v)) {
        emit("BATTERY", String(v), { property: name, id: id });
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // CLIPBOARD
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.content.ClipboardManager", "getPrimaryClip", [], function () {
    var clip = this.getPrimaryClip();
    if (clip !== null && clip.getItemCount() > 0) {
      try {
        var text = clip.getItemAt(0).getText();
        emit("CLIPBOARD", text ? text.toString() : "(non-text)");
      } catch (e) {}
    }
    return clip;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // INSTALLED APPS
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.content.pm.PackageManager", "getInstalledPackages", ["int"],
    function (flags) {
      var list = this.getInstalledPackages(flags);
      var count = list !== null ? list.size() : 0;
      emit("INSTALLED_APPS", count + " packages", { count: count, flags: flags });
      return list;
    }
  );

  hookMethod("android.content.pm.PackageManager", "getInstalledApplications", ["int"],
    function (flags) {
      var list = this.getInstalledApplications(flags);
      var count = list !== null ? list.size() : 0;
      emit("INSTALLED_APPS", count + " apps", { count: count, flags: flags, method: "getInstalledApplications" });
      return list;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // ACCOUNTS
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.accounts.AccountManager", "getAccounts", [], function () {
    var accounts = this.getAccounts();
    var info = [];
    if (accounts !== null) {
      for (var i = 0; i < accounts.length; i++) {
        info.push(accounts[i].type + ":" + accounts[i].name);
      }
    }
    emit("ACCOUNTS", info.join("|"), { count: info.length });
    return accounts;
  });

  hookMethod("android.accounts.AccountManager", "getAccountsByType", ["java.lang.String"],
    function (type) {
      var accounts = this.getAccountsByType(type);
      var info = [];
      if (accounts !== null) {
        for (var i = 0; i < accounts.length; i++) info.push(accounts[i].name.toString());
      }
      emit("ACCOUNTS", info.join("|"), { type: type, count: info.length });
      return accounts;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // CONTENT RESOLVER — contacts, SMS, GSF gservices
  // ═══════════════════════════════════════════════════════════════════════════

  var SENSITIVE_URIS = [
    "contacts", "sms", "mms", "call_log", "telephony",
    "media", "memories", "snap", "com.snapchat", "downloads",
    "gsf.gservices", "gservices", "content://com.google.android.gsf"
  ];

  hookMethod(
    "android.content.ContentResolver",
    "query",
    ["android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String"],
    function (uri, projection, selection, selectionArgs, sortOrder) {
      if (uri !== null) {
        var uriStr = uri.toString().toLowerCase();
        for (var i = 0; i < SENSITIVE_URIS.length; i++) {
          if (uriStr.indexOf(SENSITIVE_URIS[i]) !== -1) {
            emit("CONTENT_QUERY", uri.toString(), {
              provider: SENSITIVE_URIS[i],
              selection: selection,
              isGsf: uriStr.indexOf("gsf") !== -1
            });
            break;
          }
        }
      }
      return this.query(uri, projection, selection, selectionArgs, sortOrder);
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // CAMERA
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.hardware.camera2.CameraManager", "openCamera",
    ["java.lang.String", "android.hardware.camera2.CameraDevice$StateCallback", "android.os.Handler"],
    function (cameraId, callback, handler) {
      emit("CAMERA", cameraId, { api: "camera2" });
      return this.openCamera(cameraId, callback, handler);
    }
  );

  hookMethod("android.hardware.Camera", "open", ["int"], function (cameraId) {
    emit("CAMERA", String(cameraId), { api: "camera1" });
    return this.open(cameraId);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // MICROPHONE
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.media.AudioRecord", "startRecording", [], function () {
    emit("MICROPHONE", "AudioRecord.startRecording()");
    return this.startRecording();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // VALDI / KEYSTORE / CIPHER / DIGEST
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("com.snap.valdi.store.KeychainUtils", "getSecretKey", [], function () {
    var key = this.getSecretKey();
    var info = null;
    try { info = key !== null ? key.getAlgorithm() + " format=" + key.getFormat() : "null"; } catch(e) {}
    emit("VALDI_GET_SECRET_KEY", info);
    return key;
  });

  hookMethod("com.snap.valdi.store.KeychainUtils", "a", ["java.lang.String"], function (alias) {
    var result = this.a(alias);
    emit("VALDI_KEYCHAIN_OP", alias, { method: "KeychainUtils.a" });
    return result;
  });

  hookMethod("com.snap.valdi.store.KeychainUtils", "b", ["java.lang.String"], function (alias) {
    var result = this.b(alias);
    emit("VALDI_KEYCHAIN_OP", alias, { method: "KeychainUtils.b" });
    return result;
  });

  hookMethod("java.security.KeyStore", "getKey", ["java.lang.String", "[C"],
    function (alias, password) {
      var key = this.getKey(alias, password);
      var info = null;
      try { info = key !== null ? key.getAlgorithm() : "null"; } catch(e) {}
      emit("KEYSTORE_GET_KEY", alias, { algorithm: info });
      return key;
    }
  );

  hookMethod("java.security.KeyStore", "getEntry",
    ["java.lang.String", "java.security.KeyStore$ProtectionParameter"],
    function (alias, param) {
      var entry = this.getEntry(alias, param);
      emit("KEYSTORE_GET_ENTRY", alias, { hasEntry: entry !== null });
      return entry;
    }
  );

  hookMethod("java.security.KeyStore", "containsAlias", ["java.lang.String"],
    function (alias) {
      var result = this.containsAlias(alias);
      emit("KEYSTORE_CONTAINS", alias, { result: result });
      return result;
    }
  );

  hookMethod("java.security.KeyStore", "deleteEntry", ["java.lang.String"],
    function (alias) {
      this.deleteEntry(alias);
      emit("KEYSTORE_DELETE", alias);
    }
  );

  // Cipher
  hookMethod("javax.crypto.Cipher", "init", ["int", "java.security.Key"],
    function (opmode, key) {
      var modeStr = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : "mode=" + opmode;
      var alg = null;
      try { alg = key !== null ? key.getAlgorithm() : "null"; } catch(e) {}
      emit("CIPHER_INIT", modeStr, { algorithm: alg });
      return this.init(opmode, key);
    }
  );

  function bytesToInfo(javaBytes, maxHexBytes) {
    if (!javaBytes) return { hex: null, utf8: null, len: 0 };
    try {
      var arr = Java.array("byte", javaBytes);
      var len = arr.length;
      var hex = [];
      for (var i = 0; i < Math.min(len, maxHexBytes); i++) {
        hex.push(("0" + (arr[i] & 0xFF).toString(16)).slice(-2));
      }
      var hexStr = hex.join("") + (len > maxHexBytes ? "..." : "");
      var printable = 0, chars = "";
      for (var j = 0; j < Math.min(len, 200); j++) {
        var b = arr[j] & 0xFF;
        if (b >= 32 && b < 127) { printable++; chars += String.fromCharCode(b); }
        else chars += ".";
      }
      var utf8 = (printable / Math.min(len, 200) > 0.6) ? chars : null;
      return { hex: hexStr, utf8: utf8, len: len };
    } catch(e) {
      return { hex: null, utf8: null, len: 0 };
    }
  }

  function bytesToInfoFull(javaBytes) {
    if (!javaBytes) return { display: null, dedupKey: "", len: 0 };
    try {
      var arr = Java.array("byte", javaBytes);
      var len = arr.length;
      var hexParts = [];
      for (var i = 0; i < Math.min(len, 48); i++) {
        hexParts.push(("0" + (arr[i] & 0xFF).toString(16)).slice(-2));
      }
      var dedupKey = hexParts.join("") + "|" + len;
      var printable = 0, parts = [];
      var limit = Math.min(len, 512);
      for (var j = 0; j < limit; j++) {
        var b = arr[j] & 0xFF;
        if (b >= 32 && b < 127) { printable++; parts.push(String.fromCharCode(b)); }
        else parts.push("\\x" + ("0" + b.toString(16)).slice(-2));
      }
      var ratio = len > 0 ? printable / limit : 0;
      var display;
      if (ratio > 0.75) {
        display = parts.join("") + (len > 512 ? "...[+" + (len - 512) + "]" : "");
      } else {
        var hexAll = [];
        for (var k = 0; k < Math.min(len, 64); k++) {
          hexAll.push(("0" + (arr[k] & 0xFF).toString(16)).slice(-2));
        }
        display = hexAll.join("") + (len > 64 ? "...[+" + (len - 64) + "]" : "");
      }
      return { display: display, dedupKey: dedupKey, len: len };
    } catch(e) {
      return { display: null, dedupKey: "", len: 0 };
    }
  }

  hookMethod("javax.crypto.Cipher", "doFinal", ["[B"], function (input) {
    var result = this.doFinal(input);
    var alg = null;
    try { alg = this.getAlgorithm(); } catch(e) {}
    var inInfo  = bytesToInfo(input, 64);
    var outInfo = bytesToInfo(result, 64);
    var preceding = digestAccumFlush();
    var digestInputs = preceding.map(function (e) { return e.alg + "(" + e.display + ")"; });
    emit("CIPHER_DOFINAL", inInfo.utf8 || inInfo.hex, {
      algorithm: alg, inputHex: inInfo.hex, inputLen: inInfo.len,
      outputHex: outInfo.hex, outputUtf8: outInfo.utf8, outputLen: outInfo.len,
      precedingN: preceding.length, digestInputs: digestInputs
    });
    return result;
  });

  hookMethod("javax.crypto.Cipher", "doFinal", [], function () {
    var result = this.doFinal();
    var alg = null;
    try { alg = this.getAlgorithm(); } catch(e) {}
    var outInfo = bytesToInfo(result, 64);
    var preceding = digestAccumFlush();
    var digestInputs = preceding.map(function (e) { return e.alg + "(" + e.display + ")"; });
    emit("CIPHER_DOFINAL", outInfo.utf8 || outInfo.hex, {
      algorithm: alg, variant: "no-arg", outputHex: outInfo.hex,
      outputLen: outInfo.len, precedingN: preceding.length, digestInputs: digestInputs
    });
    return result;
  });

  // MessageDigest
  hookMethod("java.security.MessageDigest", "digest", ["[B"], function (input) {
    var result = this.digest(input);
    var alg = null;
    try { alg = this.getAlgorithm(); } catch(e) {}
    var info = bytesToInfoFull(input);
    digestAccumPush({ ts: Date.now(), alg: alg || "?", display: info.display || "", len: info.len });
    var dedupKey = (alg || "?") + ":" + info.dedupKey;
    if (isNew("DIGEST", dedupKey)) {
      emit("DIGEST", info.display, { algorithm: alg, inputLen: info.len });
    }
    return result;
  });

  var mdChunks = {};
  function mdKey(inst) {
    try { return inst.$handle.toString(); } catch(e) {
      try { return String(inst.hashCode()); } catch(e2) { return null; }
    }
  }
  function mdEnsure(inst) {
    var k = mdKey(inst);
    if (!k) return null;
    if (!mdChunks[k]) {
      var alg = null;
      try { alg = inst.getAlgorithm(); } catch(e) {}
      mdChunks[k] = { alg: alg || "?", chunks: [], totalLen: 0 };
    }
    return k;
  }

  hookMethod("java.security.MessageDigest", "update", ["[B"], function (input) {
    this.update(input);
    var info = bytesToInfoFull(input);
    var k = mdEnsure(this);
    if (k) { mdChunks[k].chunks.push(info.display || ""); mdChunks[k].totalLen += info.len; }
  });

  hookMethod("java.security.MessageDigest", "update", ["[B", "int", "int"], function (buf, off, len) {
    this.update(buf, off, len);
    var k = mdEnsure(this);
    if (k) {
      var sliceDisplay = null;
      try {
        var arr = Java.array("byte", buf);
        var printable = 0, parts = [];
        var end = Math.min(off + len, arr.length, off + 256);
        for (var i = off; i < end; i++) {
          var b = arr[i] & 0xFF;
          if (b >= 32 && b < 127) { printable++; parts.push(String.fromCharCode(b)); }
          else parts.push("\\x" + ("0" + b.toString(16)).slice(-2));
        }
        sliceDisplay = (parts.length > 0 && printable / parts.length > 0.75) ? parts.join("") : "[bin:" + len + "b]";
      } catch(e) { sliceDisplay = "[slice:" + len + "b]"; }
      mdChunks[k].chunks.push("[" + off + "+" + len + "] " + sliceDisplay);
      mdChunks[k].totalLen += len;
    }
  });

  hookMethod("java.security.MessageDigest", "digest", [], function () {
    var result = this.digest();
    var alg = null;
    try { alg = this.getAlgorithm(); } catch(e) {}
    var k = mdKey(this);
    var acc = k ? mdChunks[k] : null;
    if (k) delete mdChunks[k];
    var combined = (acc && acc.chunks.length > 0) ? acc.chunks.join(" | ") : "(empty)";
    var totalLen = acc ? acc.totalLen : 0;
    digestAccumPush({ ts: Date.now(), alg: alg || "?", display: combined, len: totalLen });
    var dedupKey = (alg || "?") + ":" + combined.substring(0, 80);
    if (isNew("DIGEST_UPDATE", dedupKey)) {
      emit("DIGEST_UPDATE", combined.substring(0, 400), {
        algorithm: alg, totalLen: totalLen, chunkCount: acc ? acc.chunks.length : 0
      });
    }
    return result;
  });

  hookMethod("javax.crypto.Mac", "doFinal", [], function () {
    var result = this.doFinal();
    var alg = null;
    try { alg = this.getAlgorithm(); } catch(e) {}
    if (isNew("MAC_DOFINAL", alg)) emit("MAC_DOFINAL", alg);
    return result;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SSL PINNING BYPASS
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    try {
      CertPinner.check.overload("java.lang.String", "java.util.List").implementation =
        function (hostname, certs) { emit("SSL_PIN_BYPASS", hostname, { method: "check(String,List)" }); };
    } catch(e) {}
    try {
      CertPinner["check$okhttp"].overload("java.lang.String", "java.util.List").implementation =
        function (hostname, certs) { emit("SSL_PIN_BYPASS", hostname, { method: "check$okhttp" }); };
    } catch(e) {}
  } catch(e) {}

  try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustAllImpl = Java.registerClass({
      name: "com.omnitracker.TrustAll",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function (chain, authType) {
          emit("SSL_BYPASS", authType, { action: "trust_all" });
        },
        getAcceptedIssuers: function () {
          return Java.array("java.security.cert.X509Certificate", []);
        }
      }
    });
    var trustAllCtx = SSLContext.getInstance("TLS");
    trustAllCtx.init(null, [TrustAllImpl.$new()], null);
    SSLContext.getDefault.implementation = function () { return trustAllCtx; };
    emit("SSL_BYPASS", "TrustAll SSLContext installed", { action: "init" });
  } catch(e) {}

  // PRIOR APPROACH (removed): Java.enumerateLoadedClasses + Java.use(cls) for
  // any class whose FQN contains "TrustManager" AND "snap". On Snap v13.88.1.0
  // the obfuscated FQNs (pY8, Zth, ii6, wza, ...) don't contain "snap" so the
  // filter matched ~0 classes, BUT the enumeration itself visits all ~50k
  // Snap classes and Frida's JVMTI-backed walker retains a JNI global ref per
  // Class object. Result: global reference table overflow (max=51200) with
  // 50,405 unique java.lang.Class entries → SIGABRT before signup completes.
  // See tombstones 13/14/15.
  //
  // CURRENT APPROACH: the TrustAll SSLContext installed above (lines 1388+)
  // is the default SSLContext. Any custom Snap TrustManager that delegates to
  // the default is already bypassed. Snap-specific trust classes that DON'T
  // delegate still validate cert chains — but we already see them refuse
  // OmniShield at the OkHttp/HTTP layer via OKHTTP_RESPONSE captures. The
  // class-walk bypass is not worth a crash.

  // ═══════════════════════════════════════════════════════════════════════════
  // OKHTTP — request/response capture
  // ═══════════════════════════════════════════════════════════════════════════

  function peekBody(body) {
    if (!body) return null;
    try {
      var Long = Java.use("java.lang.Long");
      var source = body.source();
      source.request(Long.MAX_VALUE.value);
      return source.buffer().clone().readUtf8();
    } catch(e) { return null; }
  }

  var realCallHooked = false;
  var realCallCandidates = ["okhttp3.internal.connection.RealCall", "okhttp3.RealCall"];
  for (var rci = 0; rci < realCallCandidates.length && !realCallHooked; rci++) {
    try {
      var RealCall = Java.use(realCallCandidates[rci]);
      RealCall.execute.overload().implementation = function () {
        var reqUrl = null, reqMethod = null;
        try { var req = this.request(); reqUrl = req.url().toString(); reqMethod = req.method(); } catch(e) {}
        var response = this.execute();
        var respCode = null, respBodyStr = null;
        try { respCode = response.code(); respBodyStr = peekBody(response.body()); } catch(e) {}
        emit("OKHTTP_RESPONSE", respBodyStr ? respBodyStr.substring(0, 400) : null, {
          url: reqUrl, method: reqMethod, status: respCode,
          bodyLen: respBodyStr ? respBodyStr.length : 0
        });
        return response;
      };
      realCallHooked = true;
    } catch(e) {}
  }

  hookMethod("okhttp3.OkHttpClient", "newCall", ["okhttp3.Request"], function (request) {
    var url = null, method = null;
    try { url = request.url().toString(); } catch(e) {}
    try { method = request.method(); } catch(e) {}
    if (isNew("OKHTTP_CALL", url)) emit("OKHTTP_CALL", url, { method: method });
    return this.newCall(request);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SETTINGS.SYSTEM — additional identity keys
  // ═══════════════════════════════════════════════════════════════════════════

  var SETTINGS_SYSTEM_KEYS = [
    "screen_brightness", "screen_off_timeout", "accelerometer_rotation",
    "ringtone", "notification_sound", "alarm_alert", "font_scale"
  ];

  hookMethod(
    "android.provider.Settings$System",
    "getString",
    ["android.content.ContentResolver", "java.lang.String"],
    function (cr, name) {
      var v = this.getString(cr, name);
      if (name) {
        var lower = name.toLowerCase();
        for (var i = 0; i < SETTINGS_SYSTEM_KEYS.length; i++) {
          if (lower === SETTINGS_SYSTEM_KEYS[i]) {
            if (isNew("SETTINGS_SYSTEM", name + "=" + v)) {
              emit("SETTINGS_SYSTEM", v, { key: name });
            }
            break;
          }
        }
      }
      return v;
    }
  );

  hookMethod(
    "android.provider.Settings$System",
    "getInt",
    ["android.content.ContentResolver", "java.lang.String", "int"],
    function (cr, name, def) {
      var v = this.getInt(cr, name, def);
      if (name) {
        var lower = name.toLowerCase();
        for (var i = 0; i < SETTINGS_SYSTEM_KEYS.length; i++) {
          if (lower === SETTINGS_SYSTEM_KEYS[i]) {
            if (isNew("SETTINGS_SYSTEM_INT", name + "=" + v)) {
              emit("SETTINGS_SYSTEM_INT", String(v), { key: name });
            }
            break;
          }
        }
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // SUBSCRIPTION MANAGER — SIM info (OmniShield hooks this heavily)
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.telephony.SubscriptionManager",
    "getActiveSubscriptionInfoList",
    [],
    function () {
      var list = this.getActiveSubscriptionInfoList();
      var count = list !== null ? list.size() : 0;
      if (isNew("SUB_INFO_LIST", count)) {
        var details = [];
        if (list !== null) {
          for (var i = 0; i < Math.min(count, 5); i++) {
            try {
              var info = list.get(i);
              details.push({
                subId: info.getSubscriptionId(),
                iccId: info.getIccId(),
                simSlot: info.getSimSlotIndex(),
                displayName: info.getDisplayName() ? info.getDisplayName().toString() : null,
                carrierName: info.getCarrierName() ? info.getCarrierName().toString() : null,
                countryIso: info.getCountryIso(),
                mcc: info.getMcc(),
                mnc: info.getMnc()
              });
            } catch (e) {}
          }
        }
        var subExtra = { count: count, details: details };
        if (count === 0) {
          var simState = getSysprop("gsm.sim.state");
          var simOp = getSysprop("gsm.sim.operator.numeric");
          if (simState && simState.indexOf("READY") !== -1) {
            subExtra.anomaly = "JAVA_EMPTY";
            subExtra.anomalyReason = "0 subs but gsm.sim.state=" + simState + " (operator=" + (simOp || "?") + ")";
            subExtra.syspropValue = "gsm.sim.state=" + simState;
          }
        }
        emit("SUBSCRIPTION_INFO", count + " subs", subExtra);
      }
      return list;
    }
  );

  hookMethod(
    "android.telephony.SubscriptionManager",
    "getActiveSubscriptionInfoForSimSlotIndex",
    ["int"],
    function (slotIndex) {
      var info = this.getActiveSubscriptionInfoForSimSlotIndex(slotIndex);
      if (info !== null && isNew("SUB_INFO_SLOT", slotIndex)) {
        emit("SUBSCRIPTION_INFO_SLOT", info.toString().substring(0, 200), { slotIndex: slotIndex });
      }
      return info;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // PACKAGE MANAGER — getPackageInfo (app signature / installer detection)
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.content.pm.PackageManager",
    "getPackageInfo",
    ["java.lang.String", "int"],
    function (packageName, flags) {
      var info = this.getPackageInfo(packageName, flags);
      // Flag 0x40 = GET_SIGNATURES, 0x8000000 = GET_SIGNING_CERTIFICATES
      if (flags & 0x40 || flags & 0x8000000) {
        if (isNew("PKG_SIGNATURE_CHECK", packageName)) {
          emit("PKG_SIGNATURE_CHECK", packageName, {
            flags: "0x" + flags.toString(16),
            hasSignatures: info !== null && info.signatures.value !== null
          });
        }
      } else if (isNew("PKG_INFO", packageName)) {
        emit("PKG_INFO", packageName, { flags: "0x" + flags.toString(16) });
      }
      return info;
    }
  );

  // getApplicationInfo — detect checks for specific packages (root/xposed/frida)
  hookMethod(
    "android.content.pm.PackageManager",
    "getApplicationInfo",
    ["java.lang.String", "int"],
    function (packageName, flags) {
      var suspicious = ["magisk", "supersu", "xposed", "frida", "lucky", "substrate", "edxposed", "lsposed"];
      var isSuspicious = false;
      var lower = packageName.toLowerCase();
      for (var i = 0; i < suspicious.length; i++) {
        if (lower.indexOf(suspicious[i]) !== -1) { isSuspicious = true; break; }
      }
      if (isSuspicious && isNew("APP_INFO_SUSPICIOUS", packageName)) {
        emit("APP_INFO_SUSPICIOUS", packageName, { flags: flags });
      }
      return this.getApplicationInfo(packageName, flags);
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // APPSET ID — Firebase AppSet (OmniShield spoofs this)
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "com.google.android.gms.appset.AppSetIdClient",
    "getAppSetIdInfo",
    [],
    function () {
      var task = this.getAppSetIdInfo();
      emit("APPSET_ID_REQUEST", "getAppSetIdInfo called");
      return task;
    }
  );

  hookMethod(
    "com.google.android.gms.appset.AppSetIdInfo",
    "getId",
    [],
    function () {
      var v = this.getId();
      if (isNew("APPSET_ID", v)) emit("APPSET_ID", v);
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // CONTENTRESOLVER.CALL — used for GSF ID, AppSearch, other providers
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.content.ContentResolver",
    "call",
    ["android.net.Uri", "java.lang.String", "java.lang.String", "android.os.Bundle"],
    function (uri, method, arg, extras) {
      var result = this.call(uri, method, arg, extras);
      var uriStr = uri !== null ? uri.toString() : "";
      if (isNew("CONTENT_CALL", uriStr + ":" + method)) {
        emit("CONTENT_CALL", uriStr, { method: method, arg: arg });
      }
      return result;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // RUNTIME.EXEC / PROCESSBUILDER — command execution (root detection)
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("java.lang.Runtime", "exec", ["java.lang.String"], function (cmd) {
    emit("RUNTIME_EXEC", cmd);
    return this.exec(cmd);
  });

  hookMethod("java.lang.Runtime", "exec", ["[Ljava.lang.String;"], function (cmdArray) {
    var cmd = "";
    try {
      for (var i = 0; i < cmdArray.length; i++) cmd += (i > 0 ? " " : "") + cmdArray[i];
    } catch (e) {}
    emit("RUNTIME_EXEC", cmd, { variant: "array" });
    return this.exec(cmdArray);
  });

  hookMethod("java.lang.ProcessBuilder", "start", [], function () {
    var cmd = "";
    try {
      var list = this.command();
      for (var i = 0; i < list.size(); i++) cmd += (i > 0 ? " " : "") + list.get(i);
    } catch (e) {}
    emit("PROCESS_START", cmd);
    return this.start();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE.EXISTS — root/frida/xposed detection probes
  // ═══════════════════════════════════════════════════════════════════════════

  var ROOT_FILE_PATTERNS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/local/su", "/data/local/bin/su", "/data/adb/magisk",
    "/data/adb/modules", "magisk", "supersu", "busybox",
    "frida", "xposed", "substrate", "edxposed", "lsposed",
    "/dev/ptmx", "/proc/self/maps"
  ];

  hookMethod("java.io.File", "exists", [], function () {
    var result = this.exists();
    var path = this.getAbsolutePath();
    if (path) {
      var lower = path.toLowerCase();
      for (var i = 0; i < ROOT_FILE_PATTERNS.length; i++) {
        if (lower.indexOf(ROOT_FILE_PATTERNS[i]) !== -1) {
          if (isNew("FILE_EXISTS_PROBE", path)) {
            emit("FILE_EXISTS_PROBE", path, { exists: result, isRootProbe: true });
          }
          break;
        }
      }
    }
    return result;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // ACCESSIBILITY — OmniShield spoofs accessibility services list
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.view.accessibility.AccessibilityManager",
    "getEnabledAccessibilityServiceList",
    ["int"],
    function (feedbackType) {
      var list = this.getEnabledAccessibilityServiceList(feedbackType);
      var count = list !== null ? list.size() : 0;
      if (isNew("ACCESSIBILITY_SERVICES", count)) {
        var names = [];
        if (list !== null) {
          for (var i = 0; i < Math.min(count, 10); i++) {
            try { names.push(list.get(i).getId()); } catch (e) {}
          }
        }
        emit("ACCESSIBILITY_SERVICES", count + " services", { count: count, services: names });
      }
      return list;
    }
  );

  hookMethod(
    "android.view.accessibility.AccessibilityManager",
    "isEnabled",
    [],
    function () {
      var v = this.isEnabled();
      if (isNew("ACCESSIBILITY_ENABLED", v)) emit("ACCESSIBILITY_ENABLED", String(v));
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // DEVICE CONFIG — OmniShield may read these for feature flags
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.provider.DeviceConfig",
    "getString",
    ["java.lang.String", "java.lang.String", "java.lang.String"],
    function (namespace, name, defaultValue) {
      var v = this.getString(namespace, name, defaultValue);
      if (isNew("DEVICE_CONFIG", namespace + "/" + name)) {
        emit("DEVICE_CONFIG", v, { namespace: namespace, name: name });
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // USAGE STATS — app usage fingerprinting
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.app.usage.UsageStatsManager",
    "queryUsageStats",
    ["int", "long", "long"],
    function (intervalType, beginTime, endTime) {
      var list = this.queryUsageStats(intervalType, beginTime, endTime);
      var count = list !== null ? list.size() : 0;
      if (isNew("USAGE_STATS", intervalType)) {
        emit("USAGE_STATS", count + " entries", { intervalType: intervalType, count: count });
      }
      return list;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // SYSTEM SERVICE — detect getSystemService calls for unusual services
  // ═══════════════════════════════════════════════════════════════════════════

  var INTERESTING_SERVICES = [
    "phone", "telephony", "location", "wifi", "connectivity",
    "bluetooth", "sensor", "account", "clipboard", "usagestats",
    "device_policy", "fingerprint", "biometric", "camera",
    "audio", "notification", "activity", "window", "display",
    "power", "battery", "alarm", "deviceidle"
  ];

  hookMethod(
    "android.app.ContextImpl",
    "getSystemService",
    ["java.lang.String"],
    function (name) {
      if (name) {
        var lower = name.toLowerCase();
        for (var i = 0; i < INTERESTING_SERVICES.length; i++) {
          if (lower === INTERESTING_SERVICES[i]) {
            if (isNew("GET_SYSTEM_SERVICE", name)) {
              emit("GET_SYSTEM_SERVICE", name);
            }
            break;
          }
        }
      }
      return this.getSystemService(name);
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // FINGERPRINT / BIOMETRIC — OmniShield may monitor these
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.hardware.fingerprint.FingerprintManager",
    "hasEnrolledFingerprints",
    [],
    function () {
      var v = this.hasEnrolledFingerprints();
      if (isNew("FINGERPRINT_ENROLLED", v)) emit("FINGERPRINT_ENROLLED", String(v));
      return v;
    }
  );

  hookMethod(
    "android.hardware.fingerprint.FingerprintManager",
    "isHardwareDetected",
    [],
    function () {
      var v = this.isHardwareDetected();
      if (isNew("FINGERPRINT_HW", v)) emit("FINGERPRINT_HW", String(v));
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // POWER / BATTERY INTENT — OmniShield spoofs battery info
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.os.PowerManager",
    "isDeviceIdleMode",
    [],
    function () {
      var v = this.isDeviceIdleMode();
      if (isNew("POWER_IDLE", v)) emit("POWER_IDLE", String(v));
      return v;
    }
  );

  hookMethod(
    "android.os.PowerManager",
    "isInteractive",
    [],
    function () {
      var v = this.isInteractive();
      if (isNew("POWER_INTERACTIVE", v)) emit("POWER_INTERACTIVE", String(v));
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // TELEPHONY — getGroupIdLevel1, getVoiceMailNumber (OmniShield hooks these)
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod("android.telephony.TelephonyManager", "getGroupIdLevel1", [], function () {
    var v = this.getGroupIdLevel1();
    if (isNew("GROUP_ID_L1", v)) emit("GROUP_ID_L1", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getVoiceMailNumber", [], function () {
    var v = this.getVoiceMailNumber();
    if (isNew("VOICEMAIL_NUMBER", v)) emit("VOICEMAIL_NUMBER", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getManualNetworkSelectionPlmn", [], function () {
    var v = this.getManualNetworkSelectionPlmn();
    if (isNew("MANUAL_PLMN", v)) emit("MANUAL_PLMN", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getTypeAllocationCode", [], function () {
    var v = this.getTypeAllocationCode();
    if (isNew("TAC_CODE", v)) emit("TAC_CODE", v);
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getCarrierIdFromSimMccMnc", [], function () {
    var v = this.getCarrierIdFromSimMccMnc();
    if (isNew("CARRIER_ID_MCC", v)) emit("CARRIER_ID_MCC", String(v));
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimCarrierId", [], function () {
    var v = this.getSimCarrierId();
    if (isNew("SIM_CARRIER_ID", v)) emit("SIM_CARRIER_ID", String(v));
    return v;
  });

  hookMethod("android.telephony.TelephonyManager", "getSimSpecificCarrierId", [], function () {
    var v = this.getSimSpecificCarrierId();
    if (isNew("SIM_SPECIFIC_CARRIER_ID", v)) emit("SIM_SPECIFIC_CARRIER_ID", String(v));
    return v;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // ANDROID KEYSTORE — Key attestation (critical for device verification)
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.security.keystore.KeyGenParameterSpec$Builder",
    "setAttestationChallenge",
    ["[B"],
    function (challenge) {
      var info = bytesToInfo(challenge, 32);
      emit("KEY_ATTESTATION_CHALLENGE", info.hex || "(empty)", {
        len: info.len,
        method: "setAttestationChallenge"
      });
      return this.setAttestationChallenge(challenge);
    }
  );

  hookMethod("java.security.KeyPairGenerator", "generateKeyPair", [], function () {
    var kp = this.generateKeyPair();
    var alg = null;
    try { alg = this.getAlgorithm(); } catch (e) {}
    if (isNew("KEYPAIR_GEN", alg)) emit("KEYPAIR_GEN", alg);
    return kp;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SYSTEM FEATURES — hasSystemFeature checks
  // ═══════════════════════════════════════════════════════════════════════════

  hookMethod(
    "android.content.pm.PackageManager",
    "hasSystemFeature",
    ["java.lang.String"],
    function (name) {
      var v = this.hasSystemFeature(name);
      if (isNew("SYSTEM_FEATURE", name)) {
        emit("SYSTEM_FEATURE", name, { result: v });
      }
      return v;
    }
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // DONE
  // ═══════════════════════════════════════════════════════════════════════════

  // ─── Deferred spoof anomaly summary ─────────────────────────────────────
  // Wait 15s for OmniShield postAppSpecialize to complete, then probe APIs
  // and compare against sysprop cache to detect discrepancies.
  setTimeout(function () {
    Java.perform(function () {
      var anomalies = [];
      try {
        var ctx = Java.use("android.app.ActivityThread")
          .currentApplication().getApplicationContext();
        var tm = Java.cast(ctx.getSystemService("phone"),
                           Java.use("android.telephony.TelephonyManager"));

        var checks = [
          { call: function() { return tm.getLine1Number(); },
            field: "PHONE_NUMBER", sp: null,
            validate: function(v) {
              if (v && v.length <= 3 && /^[a-zA-Z]+$/.test(v))
                return "Country ISO '" + v + "' returned as phone number";
              return null;
            }},
          { call: function() { return tm.getSimOperator(); },
            field: "SIM_OPERATOR", sp: "gsm.sim.operator.numeric" },
          { call: function() { return tm.getSimCountryIso(); },
            field: "SIM_COUNTRY_ISO", sp: "gsm.sim.operator.iso-country" },
          { call: function() { return tm.getNetworkOperatorName(); },
            field: "NETWORK_OPERATOR_NAME", sp: "gsm.operator.alpha" },
          { call: function() { return tm.getNetworkOperator(); },
            field: "NETWORK_OPERATOR", sp: "gsm.operator.numeric" },
          { call: function() { return String(tm.getDataNetworkType()); },
            field: "DATA_NETWORK_TYPE", sp: "gsm.network.type",
            validate: function(v) {
              var sp = getSysprop("gsm.network.type");
              if (v === "0" && sp && sp !== "0" && sp !== "")
                return "Java=UNKNOWN(0), sysprop=" + sp;
              return null;
            }}
        ];

        for (var i = 0; i < checks.length; i++) {
          try {
            var c = checks[i];
            var v = c.call();
            var issue = null;
            if (c.validate) {
              issue = c.validate(v);
            } else if (c.sp) {
              var sp = getSysprop(c.sp);
              if ((!v || v === "") && sp)
                issue = "Java empty, sysprop=" + sp;
              else if (v && sp && v !== sp)
                issue = "Java='" + v + "' vs sysprop='" + sp + "'";
            }
            if (issue) {
              anomalies.push({ field: c.field, javaValue: v || "(empty)",
                syspropValue: c.sp ? (getSysprop(c.sp) || "?") : "N/A",
                issue: issue });
            }
          } catch (e) {}
        }

        // Check subscription info
        try {
          var sm = Java.use("android.telephony.SubscriptionManager");
          var smInst = sm.from(ctx);
          var subs = smInst.getActiveSubscriptionInfoList();
          var subCount = subs !== null ? subs.size() : 0;
          var simState = getSysprop("gsm.sim.state");
          if (subCount === 0 && simState && simState.indexOf("READY") !== -1) {
            anomalies.push({ field: "SUBSCRIPTION_INFO", javaValue: "0 subs",
              syspropValue: "gsm.sim.state=" + simState,
              issue: "No subs but SIM state is READY" });
          }
        } catch (e) {}

      } catch (e) {}

      if (anomalies.length > 0) {
        send({ layer: "java", type: "SPOOF_SUMMARY",
          value: anomalies.length + " anomalies detected",
          anomalies: anomalies, syspropCache: _syspropCache,
          caller: "anomaly_detector", stack: [] });
      }
    });
  }, 15000);

  // ═══════════════════════════════════════════════════════════════════════════
  // A13+ EXPANSION — identifiers introduced / shifted in Android 13/14/15
  // ═══════════════════════════════════════════════════════════════════════════

  // ─── Context.getDeviceId() — A14+ (API 34) centralised device ID ──────────
  // New abstract API that unifies IMEI/MEID/ESN behind a single getter. Apps
  // migrating off TelephonyManager.getDeviceId use this.
  hookMethod("android.content.Context", "getDeviceId", [], function () {
    var v;
    try { v = this.getDeviceId(); } catch (e) { v = null; }
    emit("CONTEXT_DEVICE_ID", v, { method: "Context.getDeviceId() [A14+]" });
    return v;
  });
  hookMethod("android.content.ContextWrapper", "getDeviceId", [], function () {
    var v;
    try { v = this.getDeviceId(); } catch (e) { v = null; }
    emit("CONTEXT_DEVICE_ID", v, { method: "ContextWrapper.getDeviceId() [A14+]" });
    return v;
  });

  // ─── SubscriptionManager.getPhoneNumber(subId) — A13+ (API 33) ─────────────
  // Replaces TelephonyManager.getLine1Number() (deprecated API 33). Apps fall
  // back here when the legacy API returns empty on A13+.
  hookMethod("android.telephony.SubscriptionManager", "getPhoneNumber", ["int"], function (subId) {
    var v;
    try { v = this.getPhoneNumber(subId); } catch (e) { v = null; }
    emit("SUB_PHONE_NUMBER", v, { method: "SubscriptionManager.getPhoneNumber(subId) [A13+]", subId: subId });
    return v;
  });
  hookMethod("android.telephony.SubscriptionManager", "getPhoneNumber", ["int", "int"], function (subId, source) {
    var v;
    try { v = this.getPhoneNumber(subId, source); } catch (e) { v = null; }
    emit("SUB_PHONE_NUMBER", v, { method: "SubscriptionManager.getPhoneNumber(subId, source) [A13+]", subId: subId, source: source });
    return v;
  });

  // ─── Settings.Global.DEVICE_PHONE_NUMBER — fallback path for phone number ─
  // Some OEMs/carriers stash the line1 number here when TelephonyManager fails.
  // Already covered by the generic Settings.Global.getString hook, but alert-
  // class it explicitly when the key matches.
  try {
    var SettingsGlobal = Java.use("android.provider.Settings$Global");
    var origGetGlobalString = SettingsGlobal.getString.overload("android.content.ContentResolver", "java.lang.String");
    origGetGlobalString.implementation = function (resolver, name) {
      var v = origGetGlobalString.call(this, resolver, name);
      if (name === "device_phone_number" || name === "DEVICE_PHONE_NUMBER") {
        emit("DEVICE_PHONE_NUMBER_SETTING", v, { method: "Settings.Global.getString(device_phone_number)", key: name });
      } else if (name === "device_provisioned") {
        emit("SETTINGS_GLOBAL", v, { key: name });
      } else if (name === "android_id") {
        // Some OEMs mirror SSAID here too (non-standard)
        emit("ANDROID_ID", v, { method: "Settings.Global.getString(android_id)", key: name });
      } else {
        emit("SETTINGS_GLOBAL", v, { key: name });
      }
      return v;
    };
  } catch (e) {}

  // ─── TelephonyManager new A13/A14 identifiers ─────────────────────────────
  hookMethod("android.telephony.TelephonyManager", "getHalVersion", [], function () {
    var v;
    try { v = this.getHalVersion(); } catch (e) { v = null; }
    emit("TELEPHONY_HAL_VERSION", v ? String(v) : null, { method: "TelephonyManager.getHalVersion() [A12+]" });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getHalVersion", ["int"], function (halService) {
    var v;
    try { v = this.getHalVersion(halService); } catch (e) { v = null; }
    emit("TELEPHONY_HAL_VERSION", v ? String(v) : null, { method: "TelephonyManager.getHalVersion(halService) [A12+]", halService: halService });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getUiccCardsInfo", [], function () {
    var v;
    try { v = this.getUiccCardsInfo(); } catch (e) { v = null; }
    var count = -1;
    try { if (v !== null) count = v.size(); } catch (e2) {}
    emit("UICC_CARDS_INFO", "cardCount=" + count, { method: "TelephonyManager.getUiccCardsInfo() [A11+]", count: count });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getRadioAccessFamily", [], function () {
    var v;
    try { v = this.getRadioAccessFamily(); } catch (e) { v = 0; }
    emit("RADIO_ACCESS_FAMILY", "0x" + (v >>> 0).toString(16), { method: "TelephonyManager.getRadioAccessFamily()" });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getTypeAllocationCode", [], function () {
    var v;
    try { v = this.getTypeAllocationCode(); } catch (e) { v = null; }
    emit("TYPE_ALLOCATION_CODE", v, { method: "TelephonyManager.getTypeAllocationCode() [A14+]" });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getTypeAllocationCode", ["int"], function (slot) {
    var v;
    try { v = this.getTypeAllocationCode(slot); } catch (e) { v = null; }
    emit("TYPE_ALLOCATION_CODE", v, { method: "TelephonyManager.getTypeAllocationCode(slot) [A14+]", slot: slot });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getManufacturerCode", [], function () {
    var v;
    try { v = this.getManufacturerCode(); } catch (e) { v = null; }
    emit("MANUFACTURER_CODE", v, { method: "TelephonyManager.getManufacturerCode() [A14+]" });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getManufacturerCode", ["int"], function (slot) {
    var v;
    try { v = this.getManufacturerCode(slot); } catch (e) { v = null; }
    emit("MANUFACTURER_CODE", v, { method: "TelephonyManager.getManufacturerCode(slot) [A14+]", slot: slot });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getCarrierIdFromSimMccMnc", [], function () {
    var v;
    try { v = this.getCarrierIdFromSimMccMnc(); } catch (e) { v = 0; }
    emit("CARRIER_ID", v, { method: "TelephonyManager.getCarrierIdFromSimMccMnc() [A10+]" });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getSimCarrierId", [], function () {
    var v;
    try { v = this.getSimCarrierId(); } catch (e) { v = 0; }
    emit("CARRIER_ID", v, { method: "TelephonyManager.getSimCarrierId()" });
    return v;
  });
  hookMethod("android.telephony.TelephonyManager", "getSimSpecificCarrierId", [], function () {
    var v;
    try { v = this.getSimSpecificCarrierId(); } catch (e) { v = 0; }
    emit("CARRIER_ID", v, { method: "TelephonyManager.getSimSpecificCarrierId()" });
    return v;
  });

  // ─── MediaDrm provisioning + extended properties (Widevine L1/L3 ID) ──────
  // provisionDevice triggers a provisioning request that carries the stable
  // device unique ID; the property getters return ephemeral session IDs plus
  // the long-lived deviceUniqueId used for server-side correlation.
  hookMethod("android.media.MediaDrm", "getProvisionRequest", [], function () {
    var v;
    try { v = this.getProvisionRequest(); } catch (e) { v = null; }
    var size = -1;
    try { if (v !== null) { var data = v.getData(); if (data !== null) size = data.length; } } catch (e2) {}
    emit("WIDEVINE_PROVISIONING_REQUEST", "size=" + size, { method: "MediaDrm.getProvisionRequest()", size: size });
    return v;
  });
  hookMethod("android.media.MediaDrm", "provideProvisionResponse", ["[B"], function (response) {
    emit("WIDEVINE_PROVISIONING_RESPONSE", "bytes=" + (response !== null ? response.length : 0), { method: "MediaDrm.provideProvisionResponse(bytes)" });
    return this.provideProvisionResponse(response);
  });
  hookMethod("android.media.MediaDrm", "openSession", [], function () {
    var v;
    try { v = this.openSession(); } catch (e) { v = null; }
    var hex = null;
    try { if (v !== null) { hex = ""; for (var i = 0; i < v.length && i < 32; i++) { var b = (v[i] & 0xFF).toString(16); hex += (b.length === 1 ? "0" : "") + b; } } } catch (e2) {}
    emit("WIDEVINE_SESSION_ID", hex, { method: "MediaDrm.openSession()" });
    return v;
  });
  hookMethod("android.media.MediaDrm", "openSession", ["int"], function (level) {
    var v;
    try { v = this.openSession(level); } catch (e) { v = null; }
    var hex = null;
    try { if (v !== null) { hex = ""; for (var i = 0; i < v.length && i < 32; i++) { var b = (v[i] & 0xFF).toString(16); hex += (b.length === 1 ? "0" : "") + b; } } } catch (e2) {}
    emit("WIDEVINE_SESSION_ID", hex, { method: "MediaDrm.openSession(level)", level: level });
    return v;
  });
  // Extended MediaDrm property keys — getPropertyString is already hooked
  // upstream, but alert on the high-signal key names and also cover the
  // byteArray variants for provisioningUniqueId / deviceUniqueId (A11+).
  try {
    var MediaDrm = Java.use("android.media.MediaDrm");
    if (MediaDrm.getPropertyByteArray) {
      var origGetByteArr = MediaDrm.getPropertyByteArray.overload("java.lang.String");
      origGetByteArr.implementation = function (key) {
        var v = origGetByteArr.call(this, key);
        var hex = null;
        try { if (v !== null) { hex = ""; for (var i = 0; i < v.length && i < 64; i++) { var b = (v[i] & 0xFF).toString(16); hex += (b.length === 1 ? "0" : "") + b; } } } catch (e) {}
        var type = "MEDIA_DRM_PROP_BYTES";
        if (key === "deviceUniqueId" || key === "WIDEVINE_DEVICE_ID") type = "WIDEVINE_DEVICE_UNIQUE_ID";
        else if (key === "provisioningUniqueId") type = "WIDEVINE_PROVISIONING_ID";
        else if (key === "serviceCertificate") type = "WIDEVINE_SERVICE_CERT";
        emit(type, hex, { method: "MediaDrm.getPropertyByteArray()", key: key });
        return v;
      };
    }
  } catch (e) {}

  // ─── UWB — A12+ (API 31) Ultra-WideBand identifiers ───────────────────────
  hookMethod("android.uwb.UwbManager", "getSpecificationInfo", [], function () {
    var v;
    try { v = this.getSpecificationInfo(); } catch (e) { v = null; }
    emit("UWB_SPEC_INFO", v ? String(v) : null, { method: "UwbManager.getSpecificationInfo() [A12+]" });
    return v;
  });
  hookMethod("android.uwb.UwbManager", "getChipInfos", [], function () {
    var v;
    try { v = this.getChipInfos(); } catch (e) { v = null; }
    var count = -1;
    try { if (v !== null) count = v.size(); } catch (e2) {}
    emit("UWB_CHIP_ID", "chips=" + count, { method: "UwbManager.getChipInfos() [A13+]", count: count });
    return v;
  });
  hookMethod("android.uwb.UwbManager", "getDefaultChipId", [], function () {
    var v;
    try { v = this.getDefaultChipId(); } catch (e) { v = null; }
    emit("UWB_CHIP_ID", v, { method: "UwbManager.getDefaultChipId() [A13+]" });
    return v;
  });

  // ─── NFC — stable per-device NFC hardware identifier ──────────────────────
  hookMethod("android.nfc.NfcAdapter", "getDefaultAdapter", ["android.content.Context"], function (ctx) {
    var v;
    try { v = this.getDefaultAdapter(ctx); } catch (e) { v = null; }
    emit("NFC_ADAPTER", v !== null ? "present" : "null", { method: "NfcAdapter.getDefaultAdapter()" });
    return v;
  });
  hookMethod("android.nfc.NfcAdapter", "isEnabled", [], function () {
    var v;
    try { v = this.isEnabled(); } catch (e) { v = false; }
    emit("NFC_ENABLED", v ? "true" : "false", { method: "NfcAdapter.isEnabled()" });
    return v;
  });
  // The stable NFC controller identifier, if available on the platform
  hookMethod("android.nfc.tech.NfcA", "getTag", [], function () {
    var v;
    try { v = this.getTag(); } catch (e) { v = null; }
    var idHex = null;
    try {
      if (v !== null) {
        var id = v.getId();
        if (id !== null) { idHex = ""; for (var i = 0; i < id.length && i < 32; i++) { var b = (id[i] & 0xFF).toString(16); idHex += (b.length === 1 ? "0" : "") + b; } }
      }
    } catch (e2) {}
    emit("NFC_ID", idHex, { method: "NfcA.getTag().getId()" });
    return v;
  });

  // ─── Bluetooth LE address (distinct from public BT MAC on A10+) ───────────
  // getAddress() returns "02:00:00:00:00:00" since A6, but LE address via
  // reflection on BluetoothAdapter internals can still leak the real address.
  hookMethod("android.bluetooth.BluetoothDevice", "getAddress", [], function () {
    var v;
    try { v = this.getAddress(); } catch (e) { v = null; }
    emit("BT_BLE_ADDRESS", v, { method: "BluetoothDevice.getAddress()" });
    return v;
  });
  hookMethod("android.bluetooth.BluetoothDevice", "getName", [], function () {
    var v;
    try { v = this.getName(); } catch (e) { v = null; }
    emit("BT_DEVICE_NAME", v, { method: "BluetoothDevice.getName()" });
    return v;
  });
  hookMethod("android.bluetooth.BluetoothDevice", "getAlias", [], function () {
    var v;
    try { v = this.getAlias(); } catch (e) { v = null; }
    emit("BT_DEVICE_ALIAS", v, { method: "BluetoothDevice.getAlias() [A9+]" });
    return v;
  });

  // ─── Biometric hardware fingerprinting (enrolled count leaks capability) ──
  hookMethod("android.hardware.biometrics.BiometricManager", "canAuthenticate", [], function () {
    var v;
    try { v = this.canAuthenticate(); } catch (e) { v = -1; }
    emit("BIOMETRIC_CAPABILITY", String(v), { method: "BiometricManager.canAuthenticate()" });
    return v;
  });
  hookMethod("android.hardware.biometrics.BiometricManager", "canAuthenticate", ["int"], function (auth) {
    var v;
    try { v = this.canAuthenticate(auth); } catch (e) { v = -1; }
    emit("BIOMETRIC_CAPABILITY", String(v), { method: "BiometricManager.canAuthenticate(auth) [A11+]", auth: auth });
    return v;
  });
  hookMethod("android.hardware.biometrics.BiometricManager$Strings", "getButtonLabel", [], function () {
    var v;
    try { v = this.getButtonLabel(); } catch (e) { v = null; }
    emit("BIOMETRIC_STRING", v ? String(v) : null, { method: "BiometricManager$Strings.getButtonLabel() [A13+]" });
    return v;
  });
  hookMethod("android.hardware.fingerprint.FingerprintManager", "getEnrolledFingerprints", [], function () {
    var v;
    try { v = this.getEnrolledFingerprints(); } catch (e) { v = null; }
    var count = -1;
    try { if (v !== null) count = v.size(); } catch (e2) {}
    emit("FINGERPRINT_ENROLLED", "count=" + count, { method: "FingerprintManager.getEnrolledFingerprints()", count: count });
    return v;
  });

  // ─── UserManager per-user identifiers ─────────────────────────────────────
  hookMethod("android.os.UserManager", "getSerialNumberForUser", ["android.os.UserHandle"], function (handle) {
    var v;
    try { v = this.getSerialNumberForUser(handle); } catch (e) { v = -1; }
    emit("USER_SERIAL_NUMBER", String(v), { method: "UserManager.getSerialNumberForUser()" });
    return v;
  });
  hookMethod("android.os.UserManager", "getUserCreationTime", ["android.os.UserHandle"], function (handle) {
    var v;
    try { v = this.getUserCreationTime(handle); } catch (e) { v = 0; }
    emit("USER_CREATION_TIME", String(v), { method: "UserManager.getUserCreationTime()" });
    return v;
  });
  hookMethod("android.os.UserHandle", "getIdentifier", [], function () {
    var v;
    try { v = this.getIdentifier(); } catch (e) { v = -1; }
    emit("USER_HANDLE_ID", String(v), { method: "UserHandle.getIdentifier()" });
    return v;
  });

  // ─── StorageManager UUIDs — StorageManager.UUID_DEFAULT + per-volume ──────
  hookMethod("android.os.storage.StorageManager", "getUuidForPath", ["java.io.File"], function (path) {
    var v;
    try { v = this.getUuidForPath(path); } catch (e) { v = null; }
    emit("STORAGE_UUID", v ? String(v) : null, { method: "StorageManager.getUuidForPath() [A8+]", path: path ? String(path) : null });
    return v;
  });
  hookMethod("android.os.storage.StorageManager", "getStorageVolumes", [], function () {
    var v;
    try { v = this.getStorageVolumes(); } catch (e) { v = null; }
    var count = -1;
    try { if (v !== null) count = v.size(); } catch (e2) {}
    emit("STORAGE_VOLUMES", "count=" + count, { method: "StorageManager.getStorageVolumes() [A7+]", count: count });
    return v;
  });

  // ─── Installer / install-source (PR-InstallFake cross-check) ──────────────
  hookMethod("android.content.pm.PackageManager", "getInstallerPackageName", ["java.lang.String"], function (pkg) {
    var v;
    try { v = this.getInstallerPackageName(pkg); } catch (e) { v = null; }
    emit("INSTALLER_PACKAGE", v, { method: "PackageManager.getInstallerPackageName()", queriedPkg: pkg });
    return v;
  });
  hookMethod("android.content.pm.PackageManager", "getInstallSourceInfo", ["java.lang.String"], function (pkg) {
    var v;
    try { v = this.getInstallSourceInfo(pkg); } catch (e) { v = null; }
    var installing = null, originating = null, initiating = null;
    try {
      if (v !== null) {
        installing = v.getInstallingPackageName ? String(v.getInstallingPackageName()) : null;
        originating = v.getOriginatingPackageName ? String(v.getOriginatingPackageName()) : null;
        initiating = v.getInitiatingPackageName ? String(v.getInitiatingPackageName()) : null;
      }
    } catch (e2) {}
    emit("INSTALL_SOURCE_INFO", installing, {
      method: "PackageManager.getInstallSourceInfo() [A11+]",
      queriedPkg: pkg,
      installing: installing,
      originating: originating,
      initiating: initiating
    });
    return v;
  });

  // ─── firstInstallTime / lastUpdateTime leak paths ─────────────────────────
  // These values survive `pm clear` and are heavy fingerprinting signals; see
  // OmniShield invariants #28 / #31 / #32 for why they matter.
  try {
    var PackageInfo = Java.use("android.content.pm.PackageInfo");
    if (PackageInfo.firstInstallTime) {
      // Field reads are hard to hook directly; instead alert whenever
      // getPackageInfo() fetches a PackageInfo we later inspect from a hook.
    }
    var origGetPkgInfo = null;
    try {
      origGetPkgInfo = Java.use("android.content.pm.PackageManager").getPackageInfo.overload("java.lang.String", "int");
      origGetPkgInfo.implementation = function (pkg, flags) {
        var v = origGetPkgInfo.call(this, pkg, flags);
        try {
          if (v !== null) {
            var fit = v.firstInstallTime.value;
            var lut = v.lastUpdateTime.value;
            emit("FIRST_INSTALL_TIME", String(fit), {
              method: "PackageManager.getPackageInfo().firstInstallTime",
              queriedPkg: pkg,
              flags: flags,
              lastUpdateTime: String(lut)
            });
          }
        } catch (e) {}
        return v;
      };
    } catch (e) {}
  } catch (e) {}

  // ─── SdkExtensions — A13+ version probing for R/S/T/U extension levels ────
  hookMethod("android.os.ext.SdkExtensions", "getExtensionVersion", ["int"], function (extension) {
    var v;
    try { v = this.getExtensionVersion(extension); } catch (e) { v = -1; }
    emit("SDK_EXTENSION_VERSION", String(v), { method: "SdkExtensions.getExtensionVersion() [A11+]", extension: extension });
    return v;
  });
  hookMethod("android.os.ext.SdkExtensions", "getAllExtensionVersions", [], function () {
    var v;
    try { v = this.getAllExtensionVersions(); } catch (e) { v = null; }
    emit("SDK_EXTENSIONS_ALL", v ? String(v) : null, { method: "SdkExtensions.getAllExtensionVersions() [A13+]" });
    return v;
  });

  // ─── HealthConnect — A14+ potential identity data source ──────────────────
  // Probe class presence without invoking: just alert on first class load.
  try {
    Java.use("androidx.health.connect.client.HealthConnectClient");
    emit("HEALTH_CONNECT", "class_present", { method: "HealthConnectClient class reachable [A14+]" });
  } catch (e) {}
  try {
    Java.use("android.health.connect.HealthConnectManager");
    emit("HEALTH_CONNECT", "manager_present", { method: "HealthConnectManager class reachable [A14+]" });
  } catch (e) {}

  // ─── Context.getDataDir / getFilesDir / getCacheDir (path fingerprinting) ─
  // The /data/user/<N>/<pkg> path leaks the user ID, which combined with
  // UserManager.getSerialNumberForUser gives a per-device-per-user signature.
  hookMethod("android.content.Context", "getDataDir", [], function () {
    var v;
    try { v = this.getDataDir(); } catch (e) { v = null; }
    emit("CONTEXT_DATA_DIR", v ? String(v) : null, { method: "Context.getDataDir() [A24+]" });
    return v;
  });

  // ─── NetworkCapabilities — transport bits expose modem capabilities ───────
  hookMethod("android.net.NetworkCapabilities", "hasTransport", ["int"], function (transport) {
    var v;
    try { v = this.hasTransport(transport); } catch (e) { v = false; }
    // TRANSPORT_BLUETOOTH=2, WIFI=1, CELLULAR=0, ETHERNET=3, VPN=4, WIFI_AWARE=5, LOWPAN=6, USB=8
    emit("NETWORK_TRANSPORT_QUERY", String(v), { method: "NetworkCapabilities.hasTransport()", transport: transport });
    return v;
  });
  hookMethod("android.net.NetworkCapabilities", "hasCapability", ["int"], function (cap) {
    var v;
    try { v = this.hasCapability(cap); } catch (e) { v = false; }
    emit("NETWORK_CAPABILITY_QUERY", String(v), { method: "NetworkCapabilities.hasCapability()", capability: cap });
    return v;
  });

  // ─── InputDevice — physical input device descriptors ──────────────────────
  hookMethod("android.view.InputDevice", "getDescriptor", [], function () {
    var v;
    try { v = this.getDescriptor(); } catch (e) { v = null; }
    emit("INPUT_DEVICE_DESCRIPTOR", v, { method: "InputDevice.getDescriptor()" });
    return v;
  });
  hookMethod("android.hardware.input.InputManager", "getInputDeviceIds", [], function () {
    var v;
    try { v = this.getInputDeviceIds(); } catch (e) { v = null; }
    var count = -1;
    try { if (v !== null) count = v.length; } catch (e2) {}
    emit("INPUT_DEVICE_IDS", "count=" + count, { method: "InputManager.getInputDeviceIds()", count: count });
    return v;
  });

  // ─── Display.getDeviceProductInfo() — A12+ factory data ───────────────────
  hookMethod("android.view.Display", "getDeviceProductInfo", [], function () {
    var v;
    try { v = this.getDeviceProductInfo(); } catch (e) { v = null; }
    var pn = null, manuId = null, modelYear = -1;
    try {
      if (v !== null) {
        pn = v.getName ? String(v.getName()) : null;
        manuId = v.getManufacturerPnpId ? String(v.getManufacturerPnpId()) : null;
        modelYear = v.getModelYear ? v.getModelYear() : -1;
      }
    } catch (e2) {}
    emit("DISPLAY_PRODUCT_INFO", pn, {
      method: "Display.getDeviceProductInfo() [A12+]",
      manufacturerPnpId: manuId,
      modelYear: modelYear
    });
    return v;
  });

  // ─── SoundTrigger / Audio hardware enumeration ────────────────────────────
  hookMethod("android.media.AudioManager", "getProperty", ["java.lang.String"], function (key) {
    var v;
    try { v = this.getProperty(key); } catch (e) { v = null; }
    emit("AUDIO_PROPERTY", v, { method: "AudioManager.getProperty()", key: key });
    return v;
  });
  hookMethod("android.media.AudioDeviceInfo", "getAddress", [], function () {
    var v;
    try { v = this.getAddress(); } catch (e) { v = null; }
    emit("AUDIO_DEVICE_ADDRESS", v, { method: "AudioDeviceInfo.getAddress() [A9+]" });
    return v;
  });

  // ─── Parcel.readString8 / readString16 — A13+ Location wire format ────────
  // Shape-exact matching: alert only when the value looks like a phone
  // number, IMEI, MAC, SSAID, or GAID. Too-noisy for every readString call.
  function looksLikeIdentifier(s) {
    if (!s || typeof s !== "string") return null;
    if (s.length < 6 || s.length > 64) return null;
    // Phone number: +<digits> of length 8-16
    if (/^\+\d{7,15}$/.test(s)) return "phone";
    // IMEI: exactly 15 digits
    if (/^\d{15}$/.test(s)) return "imei";
    // MAC: 17 chars with colons or dashes
    if (/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(s)) return "mac";
    // SSAID: 16 hex chars
    if (/^[0-9a-f]{16}$/.test(s)) return "ssaid";
    // GAID / UUID: 36 chars with dashes
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) return "uuid";
    // Advertising ID: 32 hex chars
    if (/^[0-9a-f]{32}$/.test(s)) return "hex32";
    return null;
  }
  try {
    var Parcel = Java.use("android.os.Parcel");
    // readString() — legacy alias, routes to readString16 on A13-, String8 on A13+
    if (Parcel.readString) {
      var origReadStr = Parcel.readString.overload();
      origReadStr.implementation = function () {
        var v = origReadStr.call(this);
        var kind = looksLikeIdentifier(v);
        if (kind) {
          emit("PARCEL_READ_STRING", v, { method: "Parcel.readString()", kind: kind });
        }
        return v;
      };
    }
    if (Parcel.readString8) {
      var origReadStr8 = Parcel.readString8.overload();
      origReadStr8.implementation = function () {
        var v = origReadStr8.call(this);
        var kind = looksLikeIdentifier(v);
        if (kind) {
          emit("PARCEL_READ_STRING8", v, { method: "Parcel.readString8() [A13+]", kind: kind });
        }
        return v;
      };
    }
    if (Parcel.readString16) {
      var origReadStr16 = Parcel.readString16.overload();
      origReadStr16.implementation = function () {
        var v = origReadStr16.call(this);
        var kind = looksLikeIdentifier(v);
        if (kind) {
          emit("PARCEL_READ_STRING16", v, { method: "Parcel.readString16()", kind: kind });
        }
        return v;
      };
    }
  } catch (e) {}

  // ─── PowerManager — device thermal/battery state as fingerprint ───────────
  hookMethod("android.os.PowerManager", "getCurrentThermalStatus", [], function () {
    var v;
    try { v = this.getCurrentThermalStatus(); } catch (e) { v = -1; }
    emit("THERMAL_STATUS", String(v), { method: "PowerManager.getCurrentThermalStatus() [A10+]" });
    return v;
  });

  // ─── CompanionDeviceManager — paired device IDs (A8+, expanded A12+) ──────
  hookMethod("android.companion.CompanionDeviceManager", "getAssociations", [], function () {
    var v;
    try { v = this.getAssociations(); } catch (e) { v = null; }
    var count = -1;
    try { if (v !== null) count = v.size(); } catch (e2) {}
    emit("COMPANION_ASSOCIATIONS", "count=" + count, { method: "CompanionDeviceManager.getAssociations() [A8+]", count: count });
    return v;
  });

  // ─── Phone Number Hint intent (A13+ GoogleSignIn path) ────────────────────
  // The request intent itself is a signal that Snap/GMS is about to read the
  // phone number via a SignInClient callback; correlate with Parcel readString.
  try {
    var Identity = Java.use("com.google.android.gms.auth.api.identity.Identity");
    var origGetSignIn = null;
    try {
      origGetSignIn = Identity.getSignInClient.overload("android.content.Context");
      origGetSignIn.implementation = function (ctx) {
        emit("GMS_SIGNIN_CLIENT", "getSignInClient", { method: "Identity.getSignInClient() [A13+]" });
        return origGetSignIn.call(this, ctx);
      };
    } catch (e) {}
  } catch (e) {}

  // ─── Keystore2 attestation (A12+ new API surface) ─────────────────────────
  // Upstream hooks cover KeyGenParameterSpec.setAttestationChallenge; add
  // the per-key generation call to correlate challenge → attest result.
  hookMethod("android.security.keystore2.KeyStore2", "generateKey", null, function () {
    emit("KEYSTORE2_GENERATE_KEY", "invoked", { method: "KeyStore2.generateKey() [A12+]" });
    return this.generateKey.apply(this, arguments);
  });

  // ─── KeyPairGenerator challenge + AndroidKeyStore cert chain ──────────────
  // From static analysis: Snap uses `key_attestation:generateKeyPair` +
  // `key_attestation:getCertChain` + `getSignedAttestationWithNonce`. Hooking
  // the public Android API surface catches all three.
  try {
    var KGSBuilder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
    var origSetChallenge = KGSBuilder.setAttestationChallenge.overload("[B");
    origSetChallenge.implementation = function (challenge) {
      var len = (challenge !== null) ? challenge.length : 0;
      emit("KEYSTORE_ATTESTATION_CHALLENGE", "len=" + len, {
        method: "KeyGenParameterSpec$Builder.setAttestationChallenge(byte[])",
        challengeLen: len
      });
      return origSetChallenge.call(this, challenge);
    };
  } catch (e) {}

  try {
    var KeyStoreJ = Java.use("java.security.KeyStore");
    var origGetChain = KeyStoreJ.getCertificateChain.overload("java.lang.String");
    origGetChain.implementation = function (alias) {
      var chain = origGetChain.call(this, alias);
      var n = (chain !== null) ? chain.length : 0;
      emit("KEYSTORE_CERT_CHAIN", "alias=" + alias + " certs=" + n, {
        method: "KeyStore.getCertificateChain(alias)",
        alias: String(alias || ""),
        certCount: n
      });
      return chain;
    };
  } catch (e) {}

  try {
    var KPG = Java.use("java.security.KeyPairGenerator");
    var origInit = KPG.initialize.overload("java.security.spec.AlgorithmParameterSpec");
    origInit.implementation = function (spec) {
      var hasChallenge = false;
      var specName = "";
      try {
        specName = spec.getClass().getName();
        if (specName.indexOf("KeyGenParameterSpec") !== -1) {
          var KGS = Java.use("android.security.keystore.KeyGenParameterSpec");
          var cast = Java.cast(spec, KGS);
          var ch = cast.getAttestationChallenge();
          hasChallenge = (ch !== null);
        }
      } catch (e2) {}
      emit("KEYSTORE_ATTESTATION_KEY_SPEC", "challenge=" + hasChallenge + " spec=" + specName, {
        method: "KeyPairGenerator.initialize(AlgorithmParameterSpec)",
        hasAttestationChallenge: hasChallenge,
        specClass: specName
      });
      return origInit.call(this, spec);
    };
  } catch (e) {}

  // ─── Snap-specific identifier cohorts (forensic report v13.88.1.0) ────────
  // Six cohort names: deviceId, cofDeviceId, attestationDeviceId,
  // persistentAttestationDeviceId, lagunaDeviceId, blizzardClientId.
  //
  // PRIOR APPROACH (removed): Java.enumerateLoadedClassesSync() + Java.use()
  // on every `com.snap*` class to walk fields. Snap has ~50k+ obfuscated
  // classes under its namespace; each Java.use() takes a JNI global ref and
  // Frida's proxy cache does not evict them mid-script. Result: global-ref
  // table overflow (max=51200) → JNI crashes Snap with SIGABRT before
  // signup completes. See tombstone_13 (uptime 68 s, 51,199 refs, 50,348
  // unique Class entries).
  //
  // CURRENT APPROACH: the Layer 3 Binder scanner catches the same cohort
  // names as wire-level ASCII field markers in Parcel payloads via
  // SNAP_PROTO_FIELDS (persistentAttestationDeviceId / cofDeviceId / etc.).
  // That fires on actual gRPC traffic, not on load — same signal, zero
  // JNI reference cost. No scan needed here.

  // ─── ArgosClient CppProxy + AttestationType enum ──────────────────────────
  // Classes from report: Lcom/snapchat/client/client_attestation/ArgosClient;
  // + ArgosRefresReason + AttestationType. Load-time class probe.
  var SNAP_ATTESTATION_CLASSES = [
    "com.snapchat.client.client_attestation.ArgosClient",
    "com.snapchat.client.client_attestation.ArgosClient$CppProxy",
    "com.snapchat.client.client_attestation.ArgosRefresReason",
    "com.snapchat.client.client_attestation.AttestationHeadersCallback",
    "com.snapchat.client.grpc.AttestationType",
    "com.snapchat.client.native_network_api.AttestationType",
    "com.snapchat.client.tiv.DeviceData",
    "com.snapchat.client.tiv.RequestTransactionType",
    "com.snapchat.client.tiv.TransactionDescription"
  ];
  function scanSnapAttestationClasses() {
    SNAP_ATTESTATION_CLASSES.forEach(function (cn) {
      try {
        var cls = Java.use(cn);
        var methodCount = cls.class.getDeclaredMethods().length;
        var tag = cn.indexOf("tiv.DeviceData") !== -1 ? "SNAP_TIVS_DEVICEDATA"
                : cn.indexOf("ArgosClient") !== -1 ? "SNAP_ARGOS_CLIENT"
                : cn.indexOf("AttestationType") !== -1 ? "SNAP_ATTESTATION_TYPE"
                : "SNAP_ARGOS_CLIENT";
        emit(tag, cn, {
          method: "Java.use(" + cn + ")",
          methodCount: methodCount
        });
        // Wrap ArgosClient getArgosTokenAsync + getAttestationHeaders if
        // they exist as public methods.
        if (cn.indexOf("ArgosClient") !== -1) {
          ["getArgosTokenAsync", "getAttestationHeaders",
           "getSignedAttestationWithNonce", "getAttestationPayload"].forEach(function (mn) {
            try {
              var overloads = cls[mn].overloads;
              overloads.forEach(function (ov) {
                var orig = ov;
                orig.implementation = function () {
                  emit("SNAP_ARGOS_CLIENT", cn + "." + mn + "()", {
                    method: cn + "." + mn,
                    argc: arguments.length
                  });
                  return orig.apply(this, arguments);
                };
              });
            } catch (e2) {}
          });
        }
      } catch (e) {}
    });
  }
  setTimeout(scanSnapAttestationClasses, 3500);
  setTimeout(scanSnapAttestationClasses, 12000);

  // ─── ClientAttestationInterceptor / Vendor+Google key attestation ─────────
  // PRIOR APPROACH (removed): enumerateLoadedClassesSync + Java.use() on
  // every class whose name contains "Attestation" under com.snap*. Same
  // JNI global-reference leak as the cohort scanner above — the Attestation
  // substring matches thousands of obfuscated Snap classes. Crashed Snap
  // with global ref overflow in the pre-fix capture.
  //
  // CURRENT APPROACH: the SNAP_ATTESTATION_CLASSES list above is a fixed
  // 9-entry set (ArgosClient, ArgosRefresReason, AttestationHeadersCallback,
  // AttestationType, tiv.DeviceData, RequestTransactionType,
  // TransactionDescription). We Java.use() only those explicit targets,
  // which is bounded and safe. The wrap of getArgosTokenAsync /
  // getAttestationHeaders / getSignedAttestationWithNonce /
  // getAttestationPayload fires on actual invocation — covers the
  // ClientAttestationInterceptor code path without needing to enumerate.

  send({ layer: "java", type: "__INIT__", value: "Layer 1 (Java v4) hooks loaded — Build, Telephony(+anomaly detection), Settings(Secure/Global/System), Location, Sensor, Network, MediaDrm(+provisioning), CursorWindow, Display(+productInfo), TZ/Locale, SystemProp, WebView, GAID, AppSetID, Battery, Crypto, SSL, SubscriptionMgr(+getPhoneNumber A13+), PkgManager(+installSource A11+, +firstInstallTime), Runtime.exec, File.exists, Accessibility, DeviceConfig, UsageStats, Fingerprint, Power(+thermal), KeyAttestation(+Keystore2 A12+, +setAttestationChallenge, +KeyPairGenerator.initialize, +KeyStore.getCertificateChain), SystemFeatures, Context.getDeviceId A14+, UWB A12+, NFC, BluetoothLE, BiometricStrings A13+, UserManager, StorageManager, SdkExtensions, HealthConnect A14+, Parcel.readString8 A13+, InputDevice, CompanionDevice, GMS SignInClient A13+, Snap cohorts (deviceId/cofDeviceId/attestationDeviceId/persistentAttestationDeviceId/lagunaDeviceId/blizzardClientId), Snap ArgosClient+AttestationType+TIV DeviceData, ClientAttestationInterceptor, Vendor/GoogleKeyAttestationManager + sysprop cache + SPOOF_SUMMARY(15s)", caller: "", stack: [], ts: Date.now() });
});
