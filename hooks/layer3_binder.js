/**
 * Layer 3 — Binder IPC Hooks (Expanded)
 * Intercepts Android Binder transactions by hooking ioctl() on /dev/binder.
 *
 * Expanded coverage:
 *   - All original service interfaces (Telephony, Location, etc.)
 *   - IAdvertisingIdService (GAID)
 *   - IAppSetIdService (AppSet ID)
 *   - IIdentifierService / IOAIDService (OAID)
 *   - IContentProvider (GSF ID via gservices)
 *   - ISub (SubscriptionManager — country ISO)
 *   - IKeystoreService (attestation)
 *   - ISmsRetrieverApiService (phone number hints)
 *   - IBatteryStats / IBatteryPropertiesRegistrar
 *
 * Also intercepts BC_REPLY to capture return values from services.
 */

(function () {

  // ─── Binder constants ─────────────────────────────────────────────────────

  var BINDER_WRITE_READ  = 0xC0306201;
  var BC_TRANSACTION     = 0x63;
  var BC_REPLY           = 0x65;

  var BWR_WRITE_SIZE_OFF   = 0;
  var BWR_WRITE_BUFFER_OFF = 16;

  // ─── SSAID spoofing config ──────────────────────────────────────────────
  var SPOOFED_SSAID = "deadbeefcafe1234";  // 16 hex chars — same length as real SSAID
  var REAL_SSAID = null;  // Captured on first interception for subsequent validation

  var BTD_HANDLE_OFF = 0;
  var BTD_CODE_OFF   = 8;

  // ─── Known service interfaces (expanded) ──────────────────────────────────

  var KNOWN_INTERFACES = {
    // Original
    "android.telephony.ITelephony":                  "TELEPHONY",
    "com.android.internal.telephony.ITelephony":     "TELEPHONY",
    "android.location.ILocationManager":             "LOCATION",
    "android.content.IClipboard":                    "CLIPBOARD",
    "android.content.pm.IPackageManager":            "PACKAGE_MANAGER",
    "android.app.ActivityManagerNative":             "ACTIVITY_MANAGER",
    "android.os.IUserManager":                       "USER_MANAGER",
    "android.net.IConnectivityManager":              "CONNECTIVITY",
    "android.net.wifi.IWifiManager":                 "WIFI",
    "android.bluetooth.IBluetooth":                  "BLUETOOTH",
    "android.hardware.ISensorManager":               "SENSORS",
    "android.accounts.IAccountManager":              "ACCOUNTS",
    "android.app.INotificationManager":              "NOTIFICATIONS",
    "android.media.IAudioService":                   "AUDIO",
    "com.android.internal.telephony.IPhoneSubInfo":  "PHONE_SUB_INFO",
    "android.telephony.ISms":                        "SMS",

    // NEW — OmniShield-intercepted services
    "com.google.android.gms.ads.identifier.internal.IAdvertisingIdService": "GAID_SERVICE",
    "com.google.android.gms.appset.internal.IAppSetIdService":             "APPSET_SERVICE",
    "com.android.id.IIdentifierService":             "OAID_SERVICE",
    "com.huawei.oaid.service.IOAIDService":          "OAID_SERVICE",
    "android.content.IContentProvider":              "CONTENT_PROVIDER",
    "com.android.internal.telephony.ISub":           "ISUB",
    "android.telephony.ISub":                        "ISUB",
    "android.security.IKeystoreService":             "KEYSTORE_SERVICE",
    "android.security.keystore.IKeystoreService":    "KEYSTORE_SERVICE",
    "android.security.keystore2.IKeystoreService":   "KEYSTORE_SERVICE",
    "com.google.android.gms.auth.api.phone.internal.ISmsRetrieverApiService": "SMS_RETRIEVER",
    "android.os.IBatteryPropertiesRegistrar":        "BATTERY",
    "com.android.internal.app.IBatteryStats":        "BATTERY_STATS",
    "android.view.IWindowManager":                   "WINDOW_MANAGER",
    "android.hardware.display.IDisplayManager":      "DISPLAY_MANAGER",
    "android.media.IMediaDrmService":                "MEDIA_DRM",
    "android.media.IMediaExtractorService":          "MEDIA_EXTRACTOR",
    "android.hardware.ICameraService":               "CAMERA_SERVICE",

    // NEW — additional OmniShield-intercepted services
    "android.os.IDeviceIdentifiersPolicyService":    "DEVICE_ID_POLICY",
    "android.net.INetd":                             "NETD",
    "android.hardware.fingerprint.IFingerprintService": "FINGERPRINT_SERVICE",
    "android.hardware.biometrics.IBiometricService": "BIOMETRIC_SERVICE",
    "android.os.IPowerManager":                      "POWER_MANAGER",
    "android.os.IServiceManager":                    "SERVICE_MANAGER",
    "android.app.IActivityManager":                  "ACTIVITY_MANAGER",
    "android.content.IContentService":               "CONTENT_SERVICE",
    "android.os.IDeviceIdleController":              "DEVICE_IDLE",
    "android.app.IProcessObserver":                  "PROCESS_OBSERVER",
    "android.app.IUidObserver":                      "UID_OBSERVER",
    "android.os.INetworkManagementService":          "NETWORK_MANAGEMENT",
    "android.net.ITetheringConnector":               "TETHERING",
    "com.android.internal.telephony.ICarrierConfigLoader": "CARRIER_CONFIG",
    "android.os.IStatsManager":                      "STATS_MANAGER",
    "android.os.IIncidentManager":                   "INCIDENT_MANAGER",
    "android.app.usage.IUsageStatsManager":          "USAGE_STATS",

    // A13+ additions
    "android.uwb.IUwbAdapter":                       "UWB_ADAPTER",
    "android.uwb.IUwbService":                       "UWB_SERVICE",
    "android.nfc.INfcAdapter":                       "NFC_ADAPTER",
    "android.nfc.INfcCardEmulation":                 "NFC_CARD_EMULATION",
    "android.health.connect.aidl.IHealthConnectService": "HEALTH_CONNECT_SERVICE",
    "android.adservices.common.IAdServicesCommonService": "AD_SERVICES",
    "android.adservices.adid.IAdIdService":          "AD_ID_SERVICE",
    "android.adservices.appsetid.IAppSetIdService":  "AD_APPSET_SERVICE",
    "android.security.keystore2.IKeystoreService":   "KEYSTORE2_SERVICE",
    "android.system.keystore2.IKeystoreService":     "KEYSTORE2_SERVICE",
    "android.content.pm.IPackageInstaller":          "PACKAGE_INSTALLER",
    "android.net.INetworkStatsService":              "NETWORK_STATS",
    "android.telephony.euicc.IEuiccController":      "EUICC_CONTROLLER",
    "android.telephony.ims.aidl.IImsRegistration":   "IMS_REGISTRATION",
    "android.telephony.ims.aidl.IImsConfig":         "IMS_CONFIG",
    "android.os.virtualization.IVirtualizationService": "VIRTUALIZATION",
    "android.hardware.usb.IUsbManager":              "USB_MANAGER",
    "android.hardware.location.IContextHubService":  "CONTEXT_HUB",
    "android.safetycenter.ISafetyCenterManager":     "SAFETY_CENTER",
    "android.permission.IPermissionManager":         "PERMISSION_MANAGER",
    "android.app.role.IRoleManager":                 "ROLE_MANAGER",
    "android.companion.ICompanionDeviceManager":     "COMPANION_DEVICE",
    "android.os.IVibratorService":                   "VIBRATOR",
    "android.os.vibrator.IVibratorManagerService":   "VIBRATOR_MANAGER",
    "android.hardware.camera2.ICameraService":       "CAMERA2_SERVICE",
    "android.media.IMediaRouter2Manager":            "MEDIA_ROUTER2",
    "android.view.IInputManager":                    "INPUT_MANAGER"
  };

  // Known transaction codes by interface
  var TX_CODES = {
    "TELEPHONY": {
      1:  "getDeviceId",
      2:  "getDeviceSvn",
      3:  "getImeiForSlot",
      5:  "getSubscriberId",
      7:  "getLine1Number",
      9:  "getCallState",
      10: "isSimPinEnabled",
      15: "getNetworkOperator",
      16: "getNetworkCountryIso",
      17: "getNetworkType",
      20: "getSimSerialNumber",
      22: "getSimCountryIso",
      23: "getSimOperatorName",
      24: "getSimOperator",
      27: "getSimState",
      29: "hasIccCard",
      36: "getNetworkOperatorName"
    },
    "LOCATION": {
      1:  "getLastLocation",
      2:  "requestLocationUpdates",
      3:  "removeUpdates",
      7:  "getProviders",
      9:  "getLastKnownLocation",
      12: "getAllProviders"
    },
    "CLIPBOARD": {
      1: "getPrimaryClip",
      2: "setPrimaryClip",
      3: "hasPrimaryClip",
      4: "addPrimaryClipChangedListener"
    },
    "PACKAGE_MANAGER": {
      2:  "getPackageInfo",
      5:  "getInstalledPackages",
      6:  "getInstalledApplications",
      7:  "checkPermission",
      26: "getApplicationInfo"
    },
    "PHONE_SUB_INFO": {
      1: "getDeviceId",
      2: "getDeviceSvn",
      3: "getSubscriberId",
      4: "getGroupIdLevel1",
      5: "getIccSerialNumber",
      6: "getLine1Number",
      7: "getLine1AlphaTag"
    },
    "SMS": {
      3:  "sendText",
      4:  "sendMultipartText",
      9:  "getSmsMessageForUri",
      11: "getAllMessagesFromIcc"
    },
    "WIFI": {
      1:  "getWifiServiceState",
      2:  "getConnectionInfo",
      4:  "getScanResults",
      10: "getConfiguredNetworks"
    },
    "BLUETOOTH": {
      1:  "isEnabled",
      2:  "getState",
      7:  "getAddress",
      8:  "getName",
      20: "getBondedDevices"
    },
    "ACCOUNTS": {
      1: "getAccounts",
      2: "getAccountsByFeatures",
      3: "addAccount",
      6: "confirmCredentials"
    },
    // NEW services
    "GAID_SERVICE": {
      1: "getId",
      2: "isLimitAdTrackingEnabled",
      3: "generateAdvertisingId"
    },
    "APPSET_SERVICE": {
      1: "getAppSetIdInfo"
    },
    "OAID_SERVICE": {
      1: "getOAID",
      2: "isOAIDTrackingLimited"
    },
    "CONTENT_PROVIDER": {
      1: "query",
      2: "insert",
      3: "update",
      6: "call"
    },
    "ISUB": {
      1:  "getActiveSubscriptionInfoList",
      3:  "getActiveSubscriptionInfo",
      7:  "getSubscriptionProperty",
      14: "getDefaultSubId",
      15: "getDefaultDataSubId"
    },
    "KEYSTORE_SERVICE": {
      1:  "getState",
      5:  "get",
      8:  "generateKey",
      10: "sign",
      12: "verify",
      17: "attestKey"
    },
    "SMS_RETRIEVER": {
      1: "startSmsRetriever",
      2: "getPhoneNumberHint"
    },
    "BATTERY": {
      1: "getProperty"
    },
    "DEVICE_ID_POLICY": {
      1: "getDeviceId",
      2: "getSerialForPackage"
    },
    "NETD": {
      1: "isAlive",
      5: "interfaceGetList",
      7: "interfaceGetCfg",
      28: "firewallSetInterfaceRule"
    },
    "FINGERPRINT_SERVICE": {
      1: "authenticate",
      2: "cancelAuthentication",
      5: "hasEnrolledFingerprints",
      6: "isHardwareDetected",
      10: "getEnrolledFingerprints"
    },
    "BIOMETRIC_SERVICE": {
      1: "canAuthenticate",
      2: "authenticate"
    },
    "ACTIVITY_MANAGER": {
      6:  "getRunningAppProcesses",
      15: "getMemoryInfo",
      19: "getProcessesInErrorState",
      35: "getRunningServices",
      55: "getRecentTasks",
      68: "isUserRunning"
    },
    "CARRIER_CONFIG": {
      1: "getConfigForSubId",
      3: "getDefaultCarrierServicePackageName"
    },
    "USAGE_STATS": {
      1: "queryUsageStats",
      2: "queryConfigurations",
      3: "queryEvents"
    },
    // A13+ addtions — codes are heuristic; authoritative resolution happens
    // at runtime via resolveTxCodeReflective() when the stub class is loadable.
    "UWB_ADAPTER": {
      1: "getSpecificationInfo",
      2: "getChipInfos",
      3: "getDefaultChipId",
      4: "openRanging"
    },
    "UWB_SERVICE": {
      1: "getSpecificationInfo",
      2: "registerAdapter"
    },
    "NFC_ADAPTER": {
      1: "isEnabled",
      2: "enable",
      3: "disable",
      4: "setForegroundDispatch",
      10: "getState"
    },
    "NFC_CARD_EMULATION": {
      1: "getServices",
      2: "getAidGroupForService"
    },
    "HEALTH_CONNECT_SERVICE": {
      1: "insertRecords",
      2: "updateRecords",
      3: "deleteRecords",
      4: "readRecords",
      5: "aggregateRecords",
      6: "getGrantedPermissions"
    },
    "AD_SERVICES": {
      1: "getAdServicesCommonStates",
      2: "enableAdServices",
      3: "setAdServicesEnabled"
    },
    "AD_ID_SERVICE": {
      1: "getAdId"
    },
    "AD_APPSET_SERVICE": {
      1: "getAppSetId"
    },
    "KEYSTORE2_SERVICE": {
      1: "getKeyEntry",
      2: "updateSubcomponent",
      3: "listEntries",
      4: "deleteKey",
      5: "grant",
      6: "ungrant",
      7: "getSecurityLevel",
      8: "generateKey",
      9: "createOperation",
      10: "importKey"
    },
    "PACKAGE_INSTALLER": {
      1: "createSession",
      2: "getSessionInfo",
      3: "getAllSessions",
      4: "getMySessions",
      5: "setPermissionsResult"
    },
    "NETWORK_STATS": {
      1: "getDeviceSummaryForNetwork",
      2: "getUidSummaryForNetwork",
      3: "getDataUsageHistoryForAllUid",
      4: "getMobileIfaces"
    },
    "EUICC_CONTROLLER": {
      1: "getEid",
      2: "getEuiccInfo",
      3: "getProfileList",
      4: "getProfile"
    },
    "IMS_REGISTRATION": {
      1: "getRegistrationTechnology",
      2: "addRegistrationCallback",
      3: "getRegistrationState"
    },
    "CAMERA2_SERVICE": {
      1: "connect",
      2: "connectDevice",
      3: "addListener",
      4: "getCameraIdList",
      5: "getCameraCharacteristics",
      6: "getConcurrentCameraIds",
      7: "isConcurrentSessionConfigurationSupported"
    },
    "INPUT_MANAGER": {
      1: "getInputDevice",
      2: "getInputDeviceIds",
      3: "registerInputDeviceListener"
    },
    "USB_MANAGER": {
      1: "getDeviceList",
      2: "openDevice",
      3: "getCurrentAccessory",
      4: "hasDevicePermission"
    },
    "COMPANION_DEVICE": {
      1: "associate",
      2: "getAssociations",
      3: "disassociate"
    },
    "ROLE_MANAGER": {
      1: "isRoleHeld",
      2: "getRoleHolders",
      3: "addRoleHolderAsUser"
    },
    "PERMISSION_MANAGER": {
      1: "checkPermission",
      2: "grantRuntimePermission",
      3: "revokeRuntimePermission",
      4: "getGrantedRuntimePermissions"
    },
    "CONTEXT_HUB": {
      1: "getContextHubInfo",
      2: "loadNanoApp",
      3: "unloadNanoApp"
    }
  };

  // ─── Runtime reflection of TRANSACTION_* codes ────────────────────────────
  // Many AIDL methods have compiler-generated TRANSACTION_<name> constants on
  // the Stub class that shuffle per-build. Reflection populates the authoritative
  // value once the Java VM and target classes are reachable.
  function resolveTxCodeReflective(ifaceName, methodName) {
    try {
      if (typeof Java === "undefined" || !Java.available) return null;
      var key = ifaceName + "$Stub";
      var cls;
      try { cls = Java.use(key); } catch (e) { return null; }
      var field = "TRANSACTION_" + methodName;
      try {
        var f = cls.class.getDeclaredField(field);
        f.setAccessible(true);
        return f.getInt(null);
      } catch (e) { return null; }
    } catch (e) { return null; }
  }

  // Pre-populate TX_CODES with reflective values when Java is available
  (function reflectCodes() {
    try {
      if (typeof Java === "undefined" || !Java.available) return;
      Java.perform(function () {
        var toResolve = {
          "UWB_ADAPTER": { iface: "android.uwb.IUwbAdapter", methods: ["getSpecificationInfo", "getChipInfos", "getDefaultChipId"] },
          "NFC_ADAPTER": { iface: "android.nfc.INfcAdapter", methods: ["isEnabled", "getState"] },
          "CAMERA2_SERVICE": { iface: "android.hardware.camera2.ICameraService", methods: ["getCameraIdList", "getCameraCharacteristics"] },
          "LOCATION": { iface: "android.location.ILocationManager", methods: ["getLastLocation", "getCurrentLocation"] },
          "TELEPHONY": { iface: "com.android.internal.telephony.ITelephony", methods: ["getDeviceId", "getImeiForSlot", "getSubscriberId", "getLine1Number"] }
        };
        var resolvedCount = 0;
        for (var svc in toResolve) {
          var cfg = toResolve[svc];
          for (var i = 0; i < cfg.methods.length; i++) {
            var m = cfg.methods[i];
            var code = resolveTxCodeReflective(cfg.iface, m);
            if (code !== null && typeof code === "number") {
              if (!TX_CODES[svc]) TX_CODES[svc] = {};
              TX_CODES[svc][code] = m;
              resolvedCount++;
            }
          }
        }
        if (resolvedCount > 0) {
          send({ layer: "binder", type: "__TX_REFLECT__",
            value: "Resolved " + resolvedCount + " TRANSACTION_* codes via AIDL reflection",
            ts: Date.now(), backtrace: [] });
        }
      });
    } catch (e) {}
  })();

  // ─── Helpers ──────────────────────────────────────────────────────────────

  function resolveCode(serviceName, code) {
    var map = TX_CODES[serviceName];
    if (map && map[code]) return map[code];
    return "TX_CODE_" + code;
  }

  // Try to read interface descriptor from parcel data (UTF-16LE)
  function tryReadInterface(dataPtr, dataSize) {
    if (dataSize < 8) return null;
    try {
      // Try offset 4 (standard: strict_mode_policy int32 + string len)
      var ifaceStr = tryReadInterfaceAtOffset(dataPtr, dataSize, 4);
      if (ifaceStr) return ifaceStr;

      // Try offset 8 (TSYS header: extra int32 between workSource and strLen)
      return tryReadInterfaceAtOffset(dataPtr, dataSize, 8);
    } catch (e) {
      return null;
    }
  }

  function tryReadInterfaceAtOffset(dataPtr, dataSize, offset) {
    try {
      if (offset + 4 > dataSize) return null;
      var ifaceLen = dataPtr.add(offset).readS32();
      if (ifaceLen <= 0 || ifaceLen > 256) return null;
      if (offset + 4 + ifaceLen * 2 > dataSize) return null;
      var ifaceBytes = dataPtr.add(offset + 4).readByteArray(ifaceLen * 2);
      var chars = [];
      for (var i = 0; i < ifaceLen * 2; i += 2) {
        var c = ifaceBytes[i];
        if (c === 0) break;
        chars.push(String.fromCharCode(c));
      }
      var result = chars.join("");
      // Validate — must look like a Java package name
      if (result.indexOf(".") !== -1 && result.length > 5) return result;
      return null;
    } catch (e) {
      return null;
    }
  }

  // Try to extract UTF-16LE strings from parcel data (for reply scanning)
  function extractParcelStrings(dataPtr, dataSize, maxStrings) {
    var strings = [];
    if (!dataPtr || dataSize < 8) return strings;
    try {
      var offset = 0;
      while (offset + 4 < dataSize && strings.length < maxStrings) {
        var len = dataPtr.add(offset).readS32();
        if (len > 0 && len < 256 && offset + 4 + len * 2 + 2 <= dataSize) {
          // Check for null terminator
          var nullTerm = dataPtr.add(offset + 4 + len * 2).readU16();
          if (nullTerm === 0) {
            var bytes = dataPtr.add(offset + 4).readByteArray(len * 2);
            var chars = [];
            var printable = true;
            for (var i = 0; i < len * 2; i += 2) {
              var c = bytes[i];
              var h = bytes[i + 1];
              if (h !== 0) { printable = false; break; }
              if (c >= 32 && c < 127) chars.push(String.fromCharCode(c));
              else { printable = false; break; }
            }
            if (printable && chars.length > 0) {
              strings.push({ offset: offset, value: chars.join("") });
            }
          }
        }
        offset += 4; // scan at 4-byte alignment
      }
    } catch (e) {}
    return strings;
  }

  // Try to extract doubles from parcel data (for location reply scanning)
  function extractParcelDoubles(dataPtr, dataSize) {
    var doubles = [];
    if (!dataPtr || dataSize < 16) return doubles;
    try {
      for (var offset = 0; offset + 8 <= dataSize; offset += 4) {
        var val = dataPtr.add(offset).readDouble();
        if (isFinite(val) && Math.abs(val) >= 1e-4) {
          // Check if it looks like a coordinate
          if ((Math.abs(val) <= 90.0 || Math.abs(val) <= 180.0) && Math.abs(val) >= 0.1) {
            doubles.push({ offset: offset, value: val });
          }
        }
      }
    } catch (e) {}
    return doubles;
  }

  // Check if any extracted parcel string contains a given substring
  function parcelHasString(strings, substr) {
    for (var i = 0; i < strings.length; i++) {
      if (strings[i].value.indexOf(substr) !== -1) return true;
    }
    return false;
  }

  // Find a 16-char hex string (SSAID) in a parcel reply and replace it in-place
  function findAndReplaceSsaid(dataPtr, dataSize, spoofedHex) {
    if (!dataPtr || dataSize < 40) return null;
    try {
      var offset = 0;
      while (offset + 4 < dataSize) {
        var len = dataPtr.add(offset).readS32();
        // SSAID is exactly 16 chars
        if (len === 16 && offset + 4 + 16 * 2 + 2 <= dataSize) {
          // Check null terminator
          var nullTerm = dataPtr.add(offset + 4 + 16 * 2).readU16();
          if (nullTerm === 0) {
            var bytes = dataPtr.add(offset + 4).readByteArray(32);
            var chars = [];
            var valid = true;
            for (var i = 0; i < 32; i += 2) {
              var c = bytes[i];
              var h = bytes[i + 1];
              if (h !== 0) { valid = false; break; }
              // Accept [0-9a-fA-F]
              if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70)) {
                chars.push(String.fromCharCode(c));
              } else {
                valid = false; break;
              }
            }
            if (valid && chars.length === 16) {
              var original = chars.join("");
              // Validate against known REAL_SSAID if set
              if (REAL_SSAID !== null && original !== REAL_SSAID) {
                offset += 4;
                continue;
              }
              // Capture real SSAID on first match
              if (REAL_SSAID === null) {
                REAL_SSAID = original;
              }
              // Overwrite in-place with spoofed value (UTF-16LE)
              try {
                var strDataPtr = dataPtr.add(offset + 4);
                for (var j = 0; j < 16; j++) {
                  strDataPtr.add(j * 2).writeU8(spoofedHex.charCodeAt(j));
                  strDataPtr.add(j * 2 + 1).writeU8(0);
                }
              } catch (writeErr) {
                // Try making the page writable
                try {
                  var pageBase = strDataPtr.and(ptr("0xFFFFFFFFFFFFF000"));
                  Memory.protect(pageBase, 4096, "rwx");
                  for (var j2 = 0; j2 < 16; j2++) {
                    strDataPtr.add(j2 * 2).writeU8(spoofedHex.charCodeAt(j2));
                    strDataPtr.add(j2 * 2 + 1).writeU8(0);
                  }
                } catch (protectErr) {
                  return null;  // Cannot write — give up
                }
              }
              return { original: original, offset: offset };
            }
          }
        }
        offset += 4;  // 4-byte alignment scan
      }
    } catch (e) {}
    return null;
  }

  function emit(type, value, extra) {
    var payload = {
      layer: "binder",
      type: type,
      value: value !== null && value !== undefined ? String(value) : null,
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    send(payload);
  }

  // ─── A13+ String8 Parcel wire format scanner ──────────────────────────────
  // A13+ Location replies + several AIDL variants write String8 (1-byte length
  // prefix + ASCII bytes + null terminator) instead of String16 (4-byte length
  // prefix + UTF-16LE + null terminator). The existing extractParcelStrings
  // scans only the String16 form. This helper scans String8 payloads.
  function extractParcelStrings8(dataPtr, dataSize, maxStrings) {
    var strings = [];
    if (!dataPtr || dataSize < 2) return strings;
    try {
      var offset = 0;
      while (offset + 1 < dataSize && strings.length < maxStrings) {
        // String8 format: 1-byte length prefix (signed, -1 = null) + ASCII + NUL
        var lenByte = dataPtr.add(offset).readU8();
        // A valid length is 4..255 (shorter strings too noisy)
        if (lenByte >= 4 && lenByte < 255 && offset + 1 + lenByte + 1 <= dataSize) {
          // Check null terminator
          var nullTerm = dataPtr.add(offset + 1 + lenByte).readU8();
          if (nullTerm === 0) {
            var bytes = dataPtr.add(offset + 1).readByteArray(lenByte);
            var chars = [];
            var printable = true;
            for (var i = 0; i < lenByte; i++) {
              var c = bytes[i];
              if (c >= 32 && c < 127) chars.push(String.fromCharCode(c));
              else { printable = false; break; }
            }
            if (printable && chars.length >= 4) {
              strings.push({ offset: offset, value: chars.join(""), format: "String8" });
            }
          }
        }
        offset += 1; // byte-aligned scan for String8
      }
    } catch (e) {}
    return strings;
  }

  // ─── Snap-specific endpoint + protobuf field registry ─────────────────────
  // From reports/snap_v13.88.1.0_dump/REPORT.md + FORENSIC_REPORT.md. These
  // gRPC paths (or their first-path component as a String8 inside the Parcel)
  // identify a Snap service call passing over Binder — they can appear in
  // either BC_TRANSACTION data (outbound request) or BC_REPLY data (inbound
  // response headers). We match as substring to tolerate "/prefix/" variants.
  var SNAP_ENDPOINT_TAGS = [
    // TIVS (Trusted Identity Verification Service) — NEW, was not covered
    ["/com.snapchat.auth.proto.tivs.TivService/LogTivNotificationReceived", "SNAP_TIVS"],
    ["/com.snapchat.auth.proto.tivs.TivService/LogTivNotificationDisplayed", "SNAP_TIVS"],
    ["com.snapchat.auth.proto.tivs.TivService", "SNAP_TIVS"],
    // Valis (friend-clustering / location-sharing)
    ["/snapchat.valis.ValisPreferences/", "SNAP_VALIS"],
    ["/snapchat.valis.Valis/GetFriendClusters", "SNAP_VALIS"],
    ["snapchat.valis.DeviceData", "SNAP_VALIS"],
    // Janus (auth)
    ["/snapchat.janus.api.LoginService/LoginWithPassword", "SNAP_JANUS_LOGIN"],
    ["/snapchat.janus.api.LoginService/VerifyTwoFA", "SNAP_JANUS_LOGIN"],
    ["/snapchat.janus.api.RegistrationService/RegisterWithPhoneEmail", "SNAP_JANUS_REGISTER"],
    // Gateway (bidi connect)
    ["/snapchat.gateway.Gateway/Connect", "SNAP_GATEWAY"],
    // Telephony enrollment (phone verification)
    ["/snapchat.telephony.api.PhoneEnrollmentService/ConfirmPhoneNumber", "SNAP_PHONE_ENROLL"],
    // Cameos / Minerva (AI media)
    ["/snapchat.cameos.minerva.MinervaService/", "SNAP_MINERVA"],
    ["/snapchat.cameos.generative_backgrounds.", "SNAP_GENBG"],
    // Analytics + geostorage
    ["/games.services.GeoStorage/ReadGeoData", "SNAP_GEOSTORAGE"],
    ["/marker-metadata/markers", "SNAP_MARKERS"],
    ["app-analytics-v2.snapchat.com", "SNAP_ANALYTICS"],
    ["auth.snapchat.com/oauth2/api/hermosa", "SNAP_HERMOSA"]
  ];
  // Protobuf field names that identify DeviceData-style payloads on the wire
  // (ASCII-encoded inside the Parcel byte stream — matchable as substrings).
  var SNAP_PROTO_FIELDS = [
    ["device_id", "SNAP_PROTO_DEVICE_ID"],
    ["user_agent", "SNAP_PROTO_USER_AGENT"],
    ["wifi_ssid", "SNAP_PROTO_WIFI_SSID"],
    ["persistentAttestationDeviceId", "SNAP_PROTO_PERSIST_ATTEST"],
    ["attestationDeviceId", "SNAP_PROTO_ATTEST_DEVICE_ID"],
    ["cofDeviceId", "SNAP_PROTO_COF_DEVICE_ID"],
    ["lagunaDeviceId", "SNAP_PROTO_LAGUNA"],
    ["blizzardClientId", "SNAP_PROTO_BLIZZARD"],
    ["argos_token", "SNAP_PROTO_ARGOS_TOKEN"]
  ];
  // Dedup so a single heavy call doesn't drown the log. Keyed by tag+endpoint
  // so two distinct Snap services on the same Parcel still both emit.
  var _snapEndpointSeen = {};
  var _snapEndpointSeenResetAt = 0;
  function scanSnapEndpoints(stringValues, direction) {
    if (!stringValues || stringValues.length === 0) return;
    var now = Date.now();
    // Evict dedup cache every 60 s to allow re-emission of long-running calls.
    if (now - _snapEndpointSeenResetAt > 60000) {
      _snapEndpointSeen = {};
      _snapEndpointSeenResetAt = now;
    }
    for (var i = 0; i < stringValues.length; i++) {
      var s = stringValues[i];
      if (!s || s.length < 6) continue;
      // Endpoint match
      for (var j = 0; j < SNAP_ENDPOINT_TAGS.length; j++) {
        var needle = SNAP_ENDPOINT_TAGS[j][0];
        var tag = SNAP_ENDPOINT_TAGS[j][1];
        if (s.indexOf(needle) !== -1) {
          var k = tag + "|" + needle + "|" + direction;
          if (!_snapEndpointSeen[k]) {
            _snapEndpointSeen[k] = true;
            send({
              layer: "binder", type: tag, value: s,
              direction: direction, endpoint: needle,
              ts: Date.now(), backtrace: []
            });
          }
        }
      }
      // Protobuf field match
      for (var p = 0; p < SNAP_PROTO_FIELDS.length; p++) {
        var field = SNAP_PROTO_FIELDS[p][0];
        var ptag = SNAP_PROTO_FIELDS[p][1];
        if (s.indexOf(field) !== -1) {
          var pk = ptag + "|" + direction;
          if (!_snapEndpointSeen[pk]) {
            _snapEndpointSeen[pk] = true;
            send({
              layer: "binder", type: ptag, value: s,
              direction: direction, field: field,
              ts: Date.now(), backtrace: []
            });
          }
        }
      }
    }
  }

  // ─── Track binder fds ───────────────────────────────────────────────────

  var binderFds = {};

  // ─── Pre-populate binderFds for attach mode ────────────────────────────
  // When attaching to a running process, /dev/binder was opened BEFORE our
  // hooks were injected. Scan /proc/self/fd to find pre-existing binder fds.
  (function prePopulateBinderFds() {
    try {
      var opendirPtr = Module.findExportByName("libc.so", "opendir");
      var readdirPtr = Module.findExportByName("libc.so", "readdir");
      var closedirPtr = Module.findExportByName("libc.so", "closedir");
      var readlinkPtr = Module.findExportByName("libc.so", "readlink");
      if (!opendirPtr || !readdirPtr || !closedirPtr || !readlinkPtr) return;

      var opendir  = new NativeFunction(opendirPtr, "pointer", ["pointer"]);
      var readdir  = new NativeFunction(readdirPtr, "pointer", ["pointer"]);
      var closedir = new NativeFunction(closedirPtr, "int", ["pointer"]);
      var readlink = new NativeFunction(readlinkPtr, "int", ["pointer", "pointer", "int"]);

      var dirPath = Memory.alloc(64);
      dirPath.writeUtf8String("/proc/self/fd");
      var dir = opendir(dirPath);
      if (dir.isNull()) return;

      var linkPath = Memory.alloc(256);
      var linkBuf  = Memory.alloc(512);
      var count = 0;

      var entry;
      while (!(entry = readdir(dir)).isNull()) {
        try {
          // struct dirent: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(256)
          var dName = entry.add(19).readCString();
          if (!dName || !/^\d+$/.test(dName)) continue;
          var fd = parseInt(dName, 10);

          linkPath.writeUtf8String("/proc/self/fd/" + fd);
          linkBuf.writeByteArray(new ArrayBuffer(512));
          var len = readlink(linkPath, linkBuf, 511);
          if (len > 0) {
            var target = linkBuf.readCString();
            if (target && (
              target.indexOf("/dev/binder") !== -1 ||
              target.indexOf("/dev/hwbinder") !== -1 ||
              target.indexOf("/dev/vndbinder") !== -1)) {
              binderFds[fd] = target;
              count++;
            }
          }
        } catch (e) {}
      }
      closedir(dir);

      if (count > 0) {
        send({ layer: "binder", type: "__INIT__",
          value: "Pre-populated " + count + " binder fd(s): " + JSON.stringify(binderFds),
          backtrace: [] });
      }
    } catch (e) {}
  })();

  var openPtr = Module.findExportByName("libc.so", "open");
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        try { this._path = args[0].readCString(); } catch (e) { this._path = null; }
      },
      onLeave: function (retval) {
        var fd = retval.toInt32();
        if (fd >= 0 && this._path && (
          this._path.indexOf("/dev/binder") !== -1 ||
          this._path.indexOf("/dev/hwbinder") !== -1 ||
          this._path.indexOf("/dev/vndbinder") !== -1
        )) {
          binderFds[fd] = this._path;
        }
      }
    });
  }

  var openatPtr = Module.findExportByName("libc.so", "openat");
  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter: function (args) {
        try { this._path = args[1].readCString(); } catch (e) { this._path = null; }
      },
      onLeave: function (retval) {
        var fd = retval.toInt32();
        if (fd >= 0 && this._path && (
          this._path.indexOf("/dev/binder") !== -1 ||
          this._path.indexOf("/dev/hwbinder") !== -1
        )) {
          binderFds[fd] = this._path;
        }
      }
    });
  }

  // ─── Main ioctl hook ──────────────────────────────────────────────────────

  var ioctlPtr = Module.findExportByName("libc.so", "ioctl");
  if (!ioctlPtr) {
    send({ layer: "binder", type: "__INIT__", value: "WARNING: ioctl not found — Binder hooks inactive", backtrace: [] });
    return;
  }

  // Dedup for high-frequency transactions
  var txDedup = {};
  var brUnknownLogged = false;  // Log unknown BR_* commands once (closure, not per-invocation)

  function isTxNew(service, code) {
    var key = service + ":" + code;
    if (txDedup[key]) return false;
    txDedup[key] = true;
    return true;
  }

  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      this.fd      = args[0].toInt32();
      this.request = args[1].toUInt32();
      this.argp    = args[2];

      if (this.request !== BINDER_WRITE_READ) return;
      if (!binderFds[this.fd]) return;

      try {
        var writeSize   = this.argp.add(BWR_WRITE_SIZE_OFF).readU64().toNumber();
        var writeBuffer = this.argp.add(BWR_WRITE_BUFFER_OFF).readPointer();

        if (writeSize < 8) return;

        var cmd = writeBuffer.readU32();
        if (cmd !== BC_TRANSACTION && cmd !== BC_REPLY) return;

        var btd = writeBuffer.add(4);
        var handle = btd.add(BTD_HANDLE_OFF).readU32();
        var code   = btd.add(BTD_CODE_OFF).readU32();

        var dataPtr  = null;
        var dataSize = 0;
        try {
          dataSize = btd.add(20).readU32();
          dataPtr  = btd.add(32).readPointer();
        } catch (e) {}

        // Identify service
        var iface = null;
        if (dataPtr && dataSize > 0) {
          iface = tryReadInterface(dataPtr, dataSize);
        }

        var serviceName = null;
        if (iface) {
          // Case-insensitive matching for robustness
          var ifaceLower = iface.toLowerCase();
          for (var key in KNOWN_INTERFACES) {
            if (key.toLowerCase() === ifaceLower) {
              serviceName = KNOWN_INTERFACES[key];
              break;
            }
          }
        }

        var methodName = serviceName ? resolveCode(serviceName, code) : null;
        var txType = cmd === BC_TRANSACTION ? "TX" : "REPLY";

        // ─── Snap endpoint / protobuf field scan on OUTBOUND data ─────────
        // Run on every BC_TRANSACTION with a data parcel — Snap gRPC paths
        // ride as ASCII bytes inside the Parcel payload regardless of
        // target service. Cheap: scanner is dedup'd and bounded to 512 B.
        if (cmd === BC_TRANSACTION && dataPtr && dataSize > 0) {
          try {
            var txStr16 = extractParcelStrings(dataPtr, Math.min(dataSize, 512), 16);
            var txStr8 = extractParcelStrings8(dataPtr, Math.min(dataSize, 512), 16);
            var txVals = [];
            for (var tx16 = 0; tx16 < txStr16.length; tx16++) txVals.push(txStr16[tx16].value);
            for (var tx8 = 0; tx8 < txStr8.length; tx8++) txVals.push(txStr8[tx8].value);
            if (txVals.length > 0) scanSnapEndpoints(txVals, "TX");
          } catch (eSnapTx) {}
        }

        // ─── SSAID query detection (must be BEFORE isTxNew gate) ──────────
        this._pendingSsaidQuery = false;
        if (serviceName === "CONTENT_PROVIDER" && code === 6 && dataPtr && dataSize > 0) {
          var ssaidStrings = extractParcelStrings(dataPtr, dataSize, 10);
          var hasAndroidId = false;
          var hasSettingsOrMethod = false;
          for (var si = 0; si < ssaidStrings.length; si++) {
            var sv = ssaidStrings[si].value;
            if (sv === "android_id") hasAndroidId = true;
            if (sv === "settings" || sv.indexOf("GET_secure") !== -1) hasSettingsOrMethod = true;
          }
          if (hasAndroidId && hasSettingsOrMethod) {
            this._pendingSsaidQuery = true;
          }
        }

        if (serviceName && isTxNew(serviceName, code)) {
          var extra = {
            handle: handle,
            code: code,
            interface: iface,
            service: serviceName,
            method: methodName,
            direction: txType,
            binderDev: binderFds[this.fd] || "/dev/binder",
            dataSize: dataSize
          };

          // For identity services, try to extract strings from DATA parcel
          var identityServices = [
            "GAID_SERVICE", "APPSET_SERVICE", "OAID_SERVICE",
            "CONTENT_PROVIDER", "SMS_RETRIEVER", "ISUB"
          ];
          if (dataPtr && dataSize > 0 && identityServices.indexOf(serviceName) !== -1) {
            var strings = extractParcelStrings(dataPtr, dataSize, 10);
            if (strings.length > 0) {
              extra.parcelStrings = strings.map(function(s) { return s.value; });
            }
          }

          // For location service, scan for coordinate doubles
          if (serviceName === "LOCATION" && dataPtr && dataSize > 32) {
            var doubles = extractParcelDoubles(dataPtr, dataSize);
            if (doubles.length > 0) {
              extra.parcelDoubles = doubles.map(function(d) {
                return { offset: d.offset, value: d.value.toFixed(6) };
              });
            }
          }

          emit("BINDER_" + txType + "_" + serviceName, methodName || ("code=" + code), extra);
        }

        // Also log any unknown interface with substantial data
        if (!serviceName && dataSize > 16 && iface) {
          var ifaceDedupKey = (iface || "") + ":" + code;
          if (!txDedup[ifaceDedupKey]) {
            txDedup[ifaceDedupKey] = true;
            emit("BINDER_TX_UNKNOWN", "handle=" + handle + " code=" + code, {
              handle: handle, code: code, dataSize: dataSize,
              interface: iface || "(unreadable)", direction: txType
            });
          }
        }

      } catch (e) {
        // Silently skip malformed transactions
      }
    },

    // ─── onLeave: BC_REPLY scanner + SSAID replacement ────────────────────
    onLeave: function (retval) {
      if (this.request !== BINDER_WRITE_READ) return;
      if (retval.toInt32() !== 0) return;

      try {
        // Read the read buffer (offsets verified for ARM64 32-bit binder protocol)
        var readSize = this.argp.add(24).readU64().toNumber();
        var readBuffer = this.argp.add(40).readPointer();
        if (readSize < 8) return;

        var replyCmd = readBuffer.readU32();
        // Accept BR_REPLY in both 32-bit (0x80287202) and 64-bit (0x80407202) protocols
        if (replyCmd !== 0x80287202 && replyCmd !== 0x80407202) {
          if (!brUnknownLogged && replyCmd !== 0x7206 /* BR_TRANSACTION_COMPLETE */) {
            brUnknownLogged = true;
            emit("BINDER_UNKNOWN_BR", "cmd=0x" + replyCmd.toString(16), {
              note: "Unrecognized BR command"
            });
          }
          return;
        }

        var replyBtd = readBuffer.add(4);
        var replyDataSize = replyBtd.add(20).readU32();
        var replyDataPtr = replyBtd.add(32).readPointer();
        if (!replyDataPtr || replyDataSize < 4) return;

        // ─── SSAID Replacement ─────────────────────────────────────────────
        if (this._pendingSsaidQuery) {
          var result = findAndReplaceSsaid(replyDataPtr, replyDataSize, SPOOFED_SSAID);
          if (result) {
            emit("BINDER_SSAID_REPLACED", result.original + " -> " + SPOOFED_SSAID, {
              original: result.original,
              spoofed: SPOOFED_SSAID,
              offset: result.offset,
              replyDataSize: replyDataSize
            });
          }
        }

        // ─── General reply data logging (dual-scan String16 + String8) ────
        var status = replyDataPtr.readS32();
        var replyStrings16 = extractParcelStrings(replyDataPtr, Math.min(replyDataSize, 512), 8);
        var replyStrings8 = extractParcelStrings8(replyDataPtr, Math.min(replyDataSize, 512), 8);
        var replyDoubles = extractParcelDoubles(replyDataPtr, Math.min(replyDataSize, 256));

        // Deduplicate by value (same string might appear in both scans if
        // pattern collides — rare but possible on short ASCII)
        var seen = {};
        var replyStrings = [];
        for (var si16 = 0; si16 < replyStrings16.length; si16++) {
          var e16 = replyStrings16[si16];
          if (!seen[e16.value]) { seen[e16.value] = true; e16.format = "String16"; replyStrings.push(e16); }
        }
        for (var si8 = 0; si8 < replyStrings8.length; si8++) {
          var e8 = replyStrings8[si8];
          if (!seen[e8.value]) { seen[e8.value] = true; replyStrings.push(e8); }
        }

        if (replyStrings.length > 0 || replyDoubles.length > 0) {
          var stringValues = replyStrings.map(function (s) { return s.value; });
          var stringFormats = replyStrings.map(function (s) { return s.format || "String16"; });
          var doubleValues = replyDoubles.map(function (d) { return d.value.toFixed(6); });

          emit("BINDER_REPLY_DATA", stringValues.join(" | ") || doubleValues.join(","), {
            status: status,
            dataSize: replyDataSize,
            strings: stringValues,
            stringFormats: stringFormats,
            doubles: doubleValues,
            note: "Reply data from service (String16+String8 dual-scan)"
          });

          // Snap endpoint / protobuf field scan on INBOUND reply.
          try { scanSnapEndpoints(stringValues, "REPLY"); } catch (eSnapRx) {}
        }
      } catch (e) {
        // Silently skip malformed replies
      }
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SERVICE MANAGER — detect service lookups (which services OmniShield queries)
  // ═══════════════════════════════════════════════════════════════════════════

  // Hook android.os.ServiceManager.getService at Java level for better visibility
  // This runs inside the same ioctl hook context but we also add a Java-level hook
  // if the binder layer is loaded in a Java context

  // ─── Done ─────────────────────────────────────────────────────────────────

  send({ layer: "binder", type: "__INIT__", value: "Layer 3 (Binder v4) hooks loaded — Telephony, Location, GAID, AppSetID, OAID, GSF/ContentProvider, ISub, KeyStore/KeyStore2, SmsRetriever, Battery, DeviceIdPolicy, Netd, Fingerprint, Biometric, ActivityMgr, CarrierConfig, UsageStats, + A13+: UwbAdapter, NfcAdapter, HealthConnect, AdServices, AdId, AppSetId, PackageInstaller, NetworkStats, EuiccController, ImsRegistration, Camera2Service, InputManager, UsbManager, CompanionDevice, RoleManager, PermissionManager, ContextHub + BC_REPLY scanner (32+64 bit, dual String16+String8) + SSAID replacement + attach-mode fd pre-population + runtime TRANSACTION_* reflection + Snap endpoint/protobuf scanner (TIVS/Valis/Janus/Gateway/PhoneEnroll/Minerva/GenBG/GeoStorage/Markers/Analytics/Hermosa + device_id/wifi_ssid/persistentAttestationDeviceId/cofDeviceId/lagunaDeviceId/blizzardClientId/argos_token — TX+REPLY)", ts: Date.now(), backtrace: [] });

})();
