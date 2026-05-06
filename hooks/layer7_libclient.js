/**
 * Layer 7 — libclient.so JNI observation (Snapchat-specific, opt-in)
 *
 * Target: libclient.so (Snap's gRPC engine + Cronet, 42 MB ARM64 stripped)
 *
 *   sha256:  24acdfc1938bab5b51e9f122c067f1a444e2f3f56219daf088e7365dbfac820a
 *   APK:     com.snapchat.android v13.89.0.47 (versionCode 283422)
 *   Verified against dump 2026-04-29.
 *
 * Architectural finding (2026-04-29, static recon):
 *
 *   libclient.so contains exactly 9 gRPC service paths and NONE of them is
 *   the signup RPC. The full inventory:
 *
 *     /snap.security.ArgosService/GetTokens
 *     /snapchat.gateway.Gateway/Connect
 *     /snapchat.valis.Valis/Communicate
 *     /snapchat.map.MapStyleService/GetMapStyle
 *     /snapchat.cdp.cof.CircumstancesService/targetingQuery
 *     /snapchat.content.v2.MediaDeliveryService/getClientUploadLocations
 *     /snapchat.content.v2.MediaOriginService/refreshContentReferences
 *     /snapchat.notification.PushNotificationService/AckNotification
 *     /snapchat.notification.notificationdata.PushNotificationDataRegistryService/RegisterDevice
 *     + /messagingcoreservice.MessagingCoreService/* (24 chat methods)
 *
 *   `phoneNumber` (6×) and `phone_number` (22×) appear ONLY as protobuf field
 *   names in `.rodata` — used by `MessageNano` reflection on `messaging`-domain
 *   protos (chat with phone-number contacts). Zero JNI exports take phone as
 *   a parameter. `imsi` appears once (single .rodata occurrence, log/field).
 *
 *   The 25-abr `register_block.log` captured a wire body during pre-Copihue
 *   signup. Its source is one of two: (a) Java OkHttp/HttpURLConnection/Cronet
 *   path (covered by layer1_java.js), (b) the `*_native_submit` exports in
 *   libclient.so that take a serialized `byte[]` from Java and dispatch via
 *   the internal gRPC engine. We hook BOTH (this layer + layer1) to be
 *   comprehensive.
 *
 * What this layer DOES capture:
 *
 *   1) Argos JNI exports (4 functions, identified statically):
 *      - Java_com_snapchat_client_client_attestation_ArgosClient_createInstance
 *      - Java_com_snapchat_client_client_attestation_ArgosClient_$CppProxy_native_getArgosTokenAsync
 *      - Java_com_snapchat_client_client_attestation_ArgosClient_$CppProxy_native_getAttestationHeaders
 *      - Java_com_snapchat_client_client_attestation_ArgosClient_$CppProxy_nativeDestroy
 *      Args (jstring → String) get scanned for known-identifier hits.
 *
 *   2) gRPC submit exports — Java→native transport entry points:
 *      - Java_com_snapchat_client_network_1api_NetworkApi_*native_1submit*
 *      - Java_com_snapchat_client_network_1manager_NetworkManager_*native_1submit*
 *      - Java_com_snapchat_client_native_1network_1api_NativeNetworkApi_*native_1submit*
 *      Args sampled as both jstring (URL/method) and jbyteArray (serialized
 *      protobuf body). Body is scanned for KNOWN_IDS substrings (both real
 *      AND spoofed). A hit on a SPOOFED value confirms the spoof actually
 *      reaches the wire.
 *
 *   3) Network/Messaging JNI exports matching `Java_com_snapchat_client_(network|messaging|notifications)_*`:
 *      Generic catch-all observer. Silent unless a known-identifier substring
 *      is found in any jstring arg.
 *
 *   4) Wire-body capture across the Java HTTP layer (THE missing half from
 *      layer1_java.js — added here so this single layer fully answers the
 *      "do spoofed values reach the wire?" question end-to-end):
 *      a) OkHttp `RealInterceptorChain.proceed`: full request body (no 400-char
 *         truncation) + headers, scanned for KNOWN_IDS. Body persisted as blob.
 *      b) Cronet `UploadDataProviders.create(...)` overloads: every byte[] /
 *         ByteBuffer that Snap wraps for upload gets logged + scanned BEFORE
 *         being handed to Cronet. Zero-risk pattern (we return the original
 *         provider unmodified). Captures the static-buffer case which is the
 *         common gRPC-over-HTTP/2 pattern. Streaming providers are noted but
 *         not wrapped (avoid breaking uploads).
 *      c) HttpURLConnection: hook `getOutputStream()` to wrap the returned
 *         stream with a tee that captures every byte written, scanning at
 *         flush/close. Fallback path for libs bypassing OkHttp/Cronet.
 *
 *   5) AEAD dispatch validation (2026-04-29, sanity-check):
 *      Static recon located the active ChaCha20-Poly1305 AEAD context setup at
 *      libclient.so+0xbb6220 (file offset 0x7b2220). Evidence: refs the
 *      "ChaCha20-Poly1305" rodata string 2× and is reachable from
 *      Java_..._ArgosClient_createInstance via 5 BLs:
 *        ArgosClient_createInstance(0xc1490c) → 0xc23928 → 0xc4e3a0
 *          → 0xee61f8 → 0xbb6100 → 0xbb6220
 *      0xbb6220 is also called directly from 0xb70fd0 (alternate wrapper).
 *      The CRYPTOGAMS ChaCha20 funcs at 0x101889c / 0x1018c20 / 0x10192e0
 *      and 0xa42758 are DEAD CODE (FDE-only, zero static callers) — they're
 *      Andy Polyakov's ARMv8 implementations linked in but never called by
 *      Snap; the active path is BoringSSL inline (visibility-hidden, symbols
 *      stripped). DO NOT hook the CRYPTOGAMS funcs.
 *      The hook is a minimalist register sampler (x0..x5 + retval) used to
 *      confirm 0xbb6220 fires during signup (expected ~3 firings/signup
 *      correlated with ARGOS_PLAINTEXT in layer5). Once validated, it can be
 *      extended to extract EVP_AEAD_CTX* key (X0+0..32) and nonce/plaintext
 *      pointers for offline decryption of `argos_blobs/` ciphertext.
 *
 * Cap: 200 events per session. Up to 16 byte[] blobs persisted as
 * `argos_blobs/<idx>_<type>_<len>B.bin` (sharing layer5's blob path).
 * AEAD dispatch sub-cap: 30 entries.
 *
 * Output events:
 *   LIBCLIENT_ARGOS_CALL       — Argos JNI export entry/exit
 *   LIBCLIENT_GRPC_SUBMIT      — gRPC submit body capture (with binary blob)
 *   LIBCLIENT_OKHTTP_BODY      — OkHttp request body (full, with blob)
 *   LIBCLIENT_CRONET_BODY      — Cronet UploadDataProvider byte source (with blob)
 *   LIBCLIENT_HTTPURL_BODY     — HttpURLConnection OutputStream capture (with blob)
 *   LIBCLIENT_KNOWN_ID_HIT     — known IMSI/ICCID/phone substring match
 *                                 source=jstring|grpc_body|okhttp|cronet|httpurl
 *   LIBCLIENT_AEAD_DISPATCH    — entry into AEAD context setup at
 *                                 libclient.so+0xbb6220 (ChaCha20-Poly1305 path).
 *                                 Captures x0..x5 register sample + retval.
 *                                 Sanity-check only; cap=30. Used to validate
 *                                 the active cipher path during signup.
 *
 * See also: jni/main.cpp `PR-GrpcDump` (logcat-side gRPC body dump). For
 * complete signup-flow visibility, run this layer ALONGSIDE layer1_java.js
 * (covers OkHttp/Cronet/HttpURLConnection) and read `register_block.log` style
 * post-mortems together with these JSONL events.
 */

(function () {
  var LIB_NAME = "libclient.so";
  var MAX_EMITS = 200;
  var emittedCount = 0;
  var lib = null;

  // AEAD dispatch validation (2026-04-29) — sanity-check that libclient.so+0xbb6220
  // is the active ChaCha20-Poly1305 path during Argos signup. CRYPTOGAMS funcs at
  // 0x101889c / 0x1018c20 / 0x10192e0 / 0xa42758 are dead code (FDE-only, zero
  // static callers) — DO NOT hook those.
  var AEAD_DISPATCH_OFFSET = 0xbb6220;  // file offset 0x7b2220
  var MAX_AEAD_DISPATCH = 30;
  var aeadDispatchCount = 0;

  // ─── Known identifier substrings to flag ────────────────────────────────────
  //
  // Two sources:
  //   (A) STATIC — real IDs from the physical SIM. Don't rotate. Hardcoded.
  //       A hit on any of these = OmniShield regression (real value leaked).
  //   (B) DYNAMIC — spoofed values, read from inside Snap's process at init.
  //       Snap's view of TelephonyManager/Build/Settings is what OmniShield
  //       has spoofed → reading those APIs HERE gives us the exact strings
  //       Snap will serialize. A hit on any of these = direct evidence the
  //       spoof reaches the wire (answers "is what OmniShield shows = what
  //       arrives at Snap servers?"). Auto-refreshes per master_seed rotation.
  //
  // Static REAL set is for the merlinx Claro Chile SIM (sticky to device).
  // Update if you switch to a different physical SIM.

  var KNOWN_IDS_REAL = [
    "730031454135823",          // IMSI real (Claro Chile)
    "8956031454135823430",      // ICCID real
    "+56946833905",             // phone real
    "56946833905",
    "946833905",
    // Real SSAID merlinx (from /data/adb/.omni_data/.real_ssaids)
    "123f31768a23a170",
    // Previous-rotation SSAIDs (lag-leak detection):
    "684ffe7042e1961c",         // capture A
    "902ea7c5a317a044",         // capture B
    "b215a031e93b0531"          // capture E (previous rotation, this device)
  ];
  var KNOWN_IDS = KNOWN_IDS_REAL.slice();  // mutated by populateSpoofedIds()

  function emit(type, value, extra) {
    if (emittedCount >= MAX_EMITS) return;
    emittedCount++;
    var payload = {
      layer: "libclient",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      caller: type,
      stack: [],
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    send(payload);
  }

  // emitWithBlob ships a binary buffer alongside the JSON payload.
  // android_monitor.py persists it to argos_blobs/<idx>_<type>_<len>B.bin.
  // Used for gRPC submit bodies (we want the raw protobuf for offline analysis).
  var blobsEmitted = 0;
  var MAX_BLOBS = 16;
  function emitWithBlob(type, value, extra, byteBuffer) {
    if (emittedCount >= MAX_EMITS) return;
    if (blobsEmitted >= MAX_BLOBS) {
      emit(type, value, extra);  // emit metadata without blob to stay under cap
      return;
    }
    blobsEmitted++;
    emittedCount++;
    var payload = {
      layer: "libclient",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      caller: type,
      stack: [],
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    if (byteBuffer) {
      send(payload, byteBuffer);
    } else {
      send(payload);
    }
  }

  // Convert java.nio.ByteBuffer → ArrayBuffer. Used by the native_unaryCall
  // / native_send / native_onEvent hooks below where the body rides as a
  // ByteBuffer instead of a byte[]. Returns null on failure.
  // pos/limit are read once so we don't disturb the caller's iterator state.
  function javaByteBufferToBuffer(bbObj) {
    if (!bbObj) return null;
    try {
      var pos = bbObj.position();
      var lim = bbObj.limit();
      var len = lim - pos;
      if (len <= 0 || len > 4 * 1024 * 1024) return null;
      var buf = new ArrayBuffer(len);
      var view = new Uint8Array(buf);
      // Absolute getter doesn't move the buffer's mark/position
      for (var i = 0; i < len; i++) view[i] = bbObj.get(pos + i) & 0xff;
      return { buf: buf, len: len };
    } catch (e) {
      return null;
    }
  }

  // Convert Java byte[] (jbyteArray jobject pointer) → ArrayBuffer.
  // Returns null if cast fails or if length is implausible (>1 MiB).
  function jbyteArrayToArrayBuffer(jobjPtr) {
    if (!jobjPtr || jobjPtr.isNull()) return null;
    try {
      var ja = Java.cast(jobjPtr, Java.use("[B"));
      var len = ja.length;
      if (len <= 0 || len > 1024 * 1024) return null;
      var buf = new ArrayBuffer(len);
      var view = new Uint8Array(buf);
      for (var i = 0; i < len; i++) view[i] = ja[i] & 0xff;
      return { buf: buf, len: len };
    } catch (e) {
      return null;
    }
  }

  // Scan a Uint8Array view for known-identifier substrings (ASCII + UTF-16-LE).
  // Returns {hit:..., offset:..., encoding:...} on first match, null otherwise.
  function scanBufferForKnownIds(view) {
    if (!view || view.length === 0) return null;
    // Build ASCII view as plain JS string for indexOf — bounded by length.
    // For >256KiB blobs we'd want a streaming scan, but our cap is 1MiB
    // and the call frequency is low enough.
    var asciiStr = "";
    for (var i = 0; i < view.length; i++) {
      var b = view[i];
      asciiStr += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : "\x00";
    }
    for (var k = 0; k < KNOWN_IDS.length; k++) {
      var idx = asciiStr.indexOf(KNOWN_IDS[k]);
      if (idx >= 0) return { hit: KNOWN_IDS[k], offset: idx, encoding: "ascii" };
    }
    return null;
  }

  // Format first N bytes of a Uint8Array as hex (debug head).
  function head8HexBytes(view) {
    var n = Math.min(8, view.length);
    var s = "";
    for (var i = 0; i < n; i++) {
      var v = view[i] & 0xff;
      s += (v < 16 ? "0" : "") + v.toString(16);
    }
    return s;
  }

  // ─── Protobuf field-16 extractor (TEST 1: 865B base64 unmapped token) ──────
  // Walks a top-level protobuf message and pulls every field by tag. Returns a
  // map { fieldNum: [{ wireType, offset, length, sample }] }. We only invoke
  // this on bodies > 100B so we skip control frames.
  // Wire types: 0=varint, 1=fixed64, 2=length-delimited, 5=fixed32.
  function readVarint(view, off) {
    var v = 0, shift = 0, b, j = off;
    while (j < view.length && shift < 64) {
      b = view[j];
      v += (b & 0x7f) * Math.pow(2, shift);
      j++;
      if ((b & 0x80) === 0) return { value: v, next: j };
      shift += 7;
    }
    return null;
  }
  function enumerateProtoFields(view, maxFields) {
    var out = {};
    var i = 0, count = 0;
    while (i < view.length && count < maxFields) {
      var tag = readVarint(view, i);
      if (!tag) break;
      var fieldNum = Math.floor(tag.value / 8);
      var wireType = tag.value & 0x7;
      i = tag.next;
      var entry = { wireType: wireType, tagOffset: tag.next - 1 };
      if (wireType === 0) {
        var v = readVarint(view, i); if (!v) break;
        entry.value = v.value; entry.length = v.next - i;
        i = v.next;
      } else if (wireType === 1) {
        if (i + 8 > view.length) break;
        entry.length = 8; entry.dataOffset = i; i += 8;
      } else if (wireType === 2) {
        var ln = readVarint(view, i); if (!ln) break;
        i = ln.next;
        if (i + ln.value > view.length || ln.value < 0 || ln.value > view.length) break;
        entry.length = ln.value; entry.dataOffset = i;
        i += ln.value;
      } else if (wireType === 5) {
        if (i + 4 > view.length) break;
        entry.length = 4; entry.dataOffset = i; i += 4;
      } else {
        break;
      }
      if (!out[fieldNum]) out[fieldNum] = [];
      out[fieldNum].push(entry);
      count++;
    }
    return out;
  }
  // base64 helper — NOT crypto, just for printable diagnostics
  var B64ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64Slice(view, off, len) {
    var s = "";
    var end = off + len;
    for (var i = off; i < end; i += 3) {
      var b1 = view[i] & 0xff;
      var b2 = (i + 1 < end) ? view[i + 1] & 0xff : 0;
      var b3 = (i + 2 < end) ? view[i + 2] & 0xff : 0;
      s += B64ALPHA.charAt(b1 >> 2);
      s += B64ALPHA.charAt(((b1 & 3) << 4) | (b2 >> 4));
      s += (i + 1 < end) ? B64ALPHA.charAt(((b2 & 15) << 2) | (b3 >> 6)) : "=";
      s += (i + 2 < end) ? B64ALPHA.charAt(b3 & 63) : "=";
    }
    return s;
  }
  // Detect if a length-delimited field's data looks like printable ASCII / b64
  // (likely JWT / token) vs binary. Used purely for the diagnostic emit.
  function classifyFieldShape(view, off, len) {
    if (len <= 0) return "empty";
    var sample = Math.min(64, len);
    var printable = 0, b64chars = 0, dots = 0;
    for (var i = 0; i < sample; i++) {
      var c = view[off + i] & 0xff;
      if (c >= 0x20 && c < 0x7f) printable++;
      if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) ||
          (c >= 0x61 && c <= 0x7a) || c === 0x2b || c === 0x2f ||
          c === 0x3d || c === 0x2d || c === 0x5f) b64chars++;
      if (c === 0x2e) dots++;
    }
    if (b64chars >= sample - 1 && dots === 0) return "b64-likely";
    if (b64chars >= sample - 4 && dots >= 1 && dots <= 3) return "jwt-likely";
    if (printable === sample) return "ascii";
    if (printable < sample / 2) return "binary";
    return "mixed";
  }
  // Emit per-call diagnostics for the OUTER body's field structure +
  // extract field 16 specifically (the unmapped 865B token).
  var field16EmitCount = 0;
  var MAX_FIELD16_BLOBS = 6;
  function dumpField16AndStructure(view, srcLabel, uri) {
    if (!view || view.length < 100) return;
    var fields = enumerateProtoFields(view, 64);
    var summary = {};
    for (var fnum in fields) {
      var arr = fields[fnum];
      summary[fnum] = arr.map(function (e) {
        return {
          wt: e.wireType,
          len: e.length,
          shape: (e.wireType === 2 && e.dataOffset != null)
            ? classifyFieldShape(view, e.dataOffset, e.length)
            : null
        };
      });
    }
    emit("LIBCLIENT_OUTER_BODY_STRUCT", srcLabel, {
      uri: uri || null, total_len: view.length, fields: summary
    });
    if (fields[16]) {
      for (var k = 0; k < fields[16].length; k++) {
        var e = fields[16][k];
        if (e.wireType !== 2 || e.dataOffset == null) continue;
        if (field16EmitCount >= MAX_FIELD16_BLOBS) {
          emit("LIBCLIENT_FIELD16_OVER_CAP", srcLabel, {
            uri: uri || null, length: e.length
          });
          continue;
        }
        field16EmitCount++;
        var shape = classifyFieldShape(view, e.dataOffset, e.length);
        var headHex = "";
        var hn = Math.min(32, e.length);
        for (var hi = 0; hi < hn; hi++) {
          var v = view[e.dataOffset + hi] & 0xff;
          headHex += (v < 16 ? "0" : "") + v.toString(16);
        }
        var b64Sample = b64Slice(view, e.dataOffset, Math.min(96, e.length));
        var asciiSample = "";
        for (var ai = 0; ai < Math.min(96, e.length); ai++) {
          var ac = view[e.dataOffset + ai] & 0xff;
          asciiSample += (ac >= 0x20 && ac < 0x7f) ? String.fromCharCode(ac) : ".";
        }
        // Hand the full field 16 contents off as an ArrayBuffer blob.
        var fbuf = new ArrayBuffer(e.length);
        var fview = new Uint8Array(fbuf);
        for (var bi = 0; bi < e.length; bi++) fview[bi] = view[e.dataOffset + bi];
        emitWithBlob("LIBCLIENT_FIELD16_DUMP", srcLabel, {
          uri: uri || null,
          length: e.length,
          shape: shape,
          head32hex: headHex,
          head96ascii: asciiSample,
          head96b64: b64Sample.substring(0, 128),
          source: srcLabel
        }, fbuf);
      }
    }
  }

  function emitInit(label, ok, err) {
    send({
      layer: "libclient",
      type: ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__",
      value: label,
      err: err ? String(err) : undefined,
      caller: "init",
      stack: [],
      ts: Date.now()
    });
  }

  function findLib() {
    try {
      lib = Process.getModuleByName(LIB_NAME);
      return true;
    } catch (e) {
      return false;
    }
  }

  // Convert jstring → JS String. Frida exposes Java only via Java.perform's
  // ART context, so we use Java.cast on the jobject pointer. Returns null on
  // failure — never throw inside onEnter.
  function jstringToString(jobjPtr) {
    if (!jobjPtr || jobjPtr.isNull()) return null;
    try {
      var jstr = Java.cast(jobjPtr, Java.use("java.lang.String"));
      return String(jstr);
    } catch (e) {
      return null;
    }
  }

  function scanForKnownIds(s) {
    if (!s) return null;
    for (var i = 0; i < KNOWN_IDS.length; i++) {
      if (s.indexOf(KNOWN_IDS[i]) >= 0) return KNOWN_IDS[i];
    }
    return null;
  }

  // ─── Wait for libclient.so to load ──────────────────────────────────────────
  // libclient.so loads early in Snap startup (Cronet init), but if we attach
  // before that we still need a dlopen observer to catch the load and arm
  // hooks before the first call.

  var hooksInstalled = false;
  function tryInstall() {
    if (hooksInstalled) return;
    if (findLib()) {
      hooksInstalled = true;
      installHooks();
    }
  }

  if (!findLib()) {
    emit("__INIT__", LIB_NAME + " not yet loaded — waiting (dlopen observer + 2min poll)");

    var retryCount = 0;
    var retryHandle = setInterval(function () {
      retryCount++;
      if (hooksInstalled) { clearInterval(retryHandle); return; }
      tryInstall();
      if (retryCount > 240) {
        clearInterval(retryHandle);
        if (!hooksInstalled) {
          emitInit(LIB_NAME + " not loaded after 2min — Snap may be stalled or libclient is delayed", false);
        }
      }
    }, 500);

    try {
      var dlopenExt = Module.findExportByName(null, "android_dlopen_ext");
      if (dlopenExt) {
        Interceptor.attach(dlopenExt, {
          onEnter: function (args) {
            try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
          },
          onLeave: function () {
            if (!hooksInstalled && this.path && this.path.indexOf(LIB_NAME) !== -1) {
              tryInstall();
            }
          }
        });
        emitInit("android_dlopen_ext observer installed", true);
      }
    } catch (e) {
      emitInit("android_dlopen_ext observer", false, e);
    }
  } else {
    hooksInstalled = true;
    installHooks();
  }

  // ─── Argos JNI exports ──────────────────────────────────────────────────────
  // Statically identified anchors (analyze_snap_libclient.py, 2026-04-29).
  // These are the 4 JNI exports related to Argos token generation. We hook all
  // four because pass-through observation here validates that OmniShield's
  // ArgosClient$CppProxy hooks (jni/main.cpp) are seeing the same data.

  var ARGOS_EXPORTS = [
    "Java_com_snapchat_client_client_1attestation_ArgosClient_createInstance",
    "Java_com_snapchat_client_client_1attestation_ArgosClient_00024CppProxy_native_1getArgosTokenAsync",
    "Java_com_snapchat_client_client_1attestation_ArgosClient_00024CppProxy_native_1getAttestationHeaders",
    "Java_com_snapchat_client_client_1attestation_ArgosClient_00024CppProxy_nativeDestroy"
  ];

  function installArgosHooks() {
    var installed = 0;
    for (var i = 0; i < ARGOS_EXPORTS.length; i++) {
      var name = ARGOS_EXPORTS[i];
      try {
        var addr = Module.findExportByName(LIB_NAME, name);
        if (!addr) continue;
        (function (exportName, exportAddr) {
          Interceptor.attach(exportAddr, {
            onEnter: function (args) {
              this.args = args;
              this.export = exportName;
            },
            onLeave: function (retval) {
              // args[0]=JNIEnv*, args[1]=jclass/jobject. Real args start at args[2].
              // We sample args[2..5] as jstrings — most are not, but the cast
              // failure is silent (returns null). ArgosClient_createInstance
              // takes (env, clazz) so will sample nothing useful.
              var sampled = [];
              for (var k = 2; k <= 5; k++) {
                try {
                  var s = jstringToString(this.args[k]);
                  if (s !== null && s.length > 0 && s.length < 512) {
                    sampled.push({ argIdx: k, value: s.substring(0, 240) });
                    var hit = scanForKnownIds(s);
                    if (hit) {
                      emit("LIBCLIENT_KNOWN_ID_HIT", hit, {
                        export: this.export,
                        argIdx: k,
                        context: s.substring(0, 240)
                      });
                    }
                  }
                } catch (e) { /* swallow */ }
              }
              emit("LIBCLIENT_ARGOS_CALL", this.export, {
                argsSampled: sampled,
                retval: retval ? String(retval) : null
              });
            }
          });
        })(name, addr);
        installed++;
      } catch (e) {
        emitInit(name, false, e);
      }
    }
    emitInit("Argos JNI exports installed: " + installed + "/" + ARGOS_EXPORTS.length, true);
  }

  // ─── gRPC submit hooks ──────────────────────────────────────────────────────
  // These exports are the Java→native dispatch entry points for gRPC. The
  // serialized protobuf request body rides in one of the args as a byte[].
  // We sample args[2..7] testing each as either jstring (URL/method/header)
  // or jbyteArray (body). Body buffers get scanned for KNOWN_IDS substrings
  // and persisted as binary blobs for offline analysis.
  //
  // Method-name patterns matched (substring, suffix-based):
  //   *_native_1submit                                     (legacy entry)
  //   *_native_1submitProgressiveDownloadRequest           (progressive DL)
  //   *_native_1subscribe                                  (event sub stream)
  //
  // Identified statically (analyze_snap_libclient.py output, 2026-04-29):
  //   Java_com_snapchat_client_network_1api_NetworkApi_$CppProxy_native_1submit
  //   Java_com_snapchat_client_network_1manager_NetworkManager_$CppProxy_native_1submit
  //   Java_com_snapchat_client_network_1manager_NetworkManager_$CppProxy_native_1submitProgressiveDownloadRequest
  //   Java_com_snapchat_client_native_1network_1api_NativeNetworkApi_$CppProxy_native_1submit
  //   Java_com_snapchat_client_notifications_AppEventSubscriptionManager_$CppProxy_native_1subscribe
  //   Java_com_snapchat_client_network_1types_DeckTransitionEventNotifier_$CppProxy_native_1subscribe

  function installGrpcSubmitHooks() {
    var grpcPattern = /^Java_com_snapchat_client_(native_1)?network_1(api|manager)_.*native_1submit/;
    var allExports;
    try {
      allExports = Module.enumerateExports(LIB_NAME);
    } catch (e) {
      emitInit("enumerateExports for grpc-submit failed", false, e);
      return;
    }

    var matched = [];
    for (var i = 0; i < allExports.length; i++) {
      var ex = allExports[i];
      if (ex.type !== "function") continue;
      if (!grpcPattern.test(ex.name)) continue;
      matched.push(ex);
    }

    var installed = 0;
    for (var j = 0; j < matched.length; j++) {
      var entry = matched[j];
      try {
        (function (exportName, exportAddr) {
          Interceptor.attach(exportAddr, {
            onEnter: function (args) {
              this.args = args;
              this.export = exportName;
              this.uri = null;
              this.bodyBuf = null;
              this.bodyLen = 0;
              this.bodyHit = null;
              this.bodyHead = "";

              for (var k = 2; k <= 7; k++) {
                var argp = this.args[k];
                if (!argp || argp.isNull()) continue;

                // Try jstring first — typically arg2/arg3 is the URL/method.
                if (this.uri === null) {
                  try {
                    var s = jstringToString(argp);
                    if (s !== null && s.length > 0 && s.length < 512 &&
                        (s.indexOf("/") === 0 || s.indexOf("snap") >= 0 ||
                         s.indexOf("messaging") >= 0)) {
                      this.uri = s.substring(0, 240);
                    }
                  } catch (e) { /* swallow */ }
                }

                // Try jbyteArray — typically arg3/arg4 is the serialized proto.
                if (this.bodyBuf === null) {
                  var bb = jbyteArrayToArrayBuffer(argp);
                  if (bb && bb.len > 8) {
                    this.bodyBuf = bb.buf;
                    this.bodyLen = bb.len;
                    var view = new Uint8Array(bb.buf);
                    this.bodyHead = head8HexBytes(view);
                    this.bodyHit = scanBufferForKnownIds(view);
                  }
                }
              }
            },
            onLeave: function (retval) {
              if (this.bodyBuf) {
                var meta = {
                  export: this.export,
                  length: this.bodyLen,
                  head8: this.bodyHead,
                  uri: this.uri || null
                };
                if (this.bodyHit) {
                  meta.knownIdHit = this.bodyHit.hit;
                  meta.knownIdOffset = this.bodyHit.offset;
                  meta.knownIdEncoding = this.bodyHit.encoding;
                  // High-priority emit FIRST (separate event for easy grep).
                  emit("LIBCLIENT_KNOWN_ID_HIT", this.bodyHit.hit, {
                    source: "grpc_body",
                    export: this.export,
                    uri: this.uri,
                    length: this.bodyLen,
                    offset: this.bodyHit.offset,
                    encoding: this.bodyHit.encoding
                  });
                }
                emitWithBlob("LIBCLIENT_GRPC_SUBMIT", this.uri || this.export, meta, this.bodyBuf);
                // TEST 1: parse outer-body protobuf, dump field 16 if present
                try {
                  dumpField16AndStructure(new Uint8Array(this.bodyBuf), "jni_grpc_submit", this.uri);
                } catch (eF16) {}
              } else if (this.uri) {
                // No body captured but URI was — still useful (e.g. for service-path inventory)
                emit("LIBCLIENT_GRPC_SUBMIT", this.uri, {
                  export: this.export,
                  uri: this.uri,
                  bodyCaptured: false
                });
              }
            }
          });
        })(entry.name, entry.address);
        installed++;
      } catch (e) {
        emitInit("submit-hook attach failed: " + entry.name, false, e);
      }
    }
    emitInit("gRPC submit hooks installed: " + installed + "/" + matched.length, true);
  }

  // ─── Generic network/messaging JNI export catch-all ─────────────────────────
  // Filter exports by name pattern, hook each with onLeave-only that scans
  // any jstring argument for known-identifier substrings. Only emits when a
  // match fires (otherwise zero-overhead silent observer).

  function installCatchallHooks() {
    var watched = [];
    var allExports;
    try {
      allExports = Module.enumerateExports(LIB_NAME);
    } catch (e) {
      emitInit("enumerateExports failed", false, e);
      return;
    }

    var pattern = /^Java_com_snapchat_client_(network|messaging|notifications|client_1attestation)_/;
    for (var i = 0; i < allExports.length; i++) {
      var ex = allExports[i];
      if (ex.type !== "function") continue;
      if (!pattern.test(ex.name)) continue;
      // Argos exports already covered by installArgosHooks; skip duplicates.
      if (ex.name.indexOf("ArgosClient") !== -1) continue;
      watched.push(ex);
    }

    var capped = watched.slice(0, 80);  // hard cap to keep ART stable
    var installed = 0;
    for (var j = 0; j < capped.length; j++) {
      var entry = capped[j];
      try {
        (function (exportName, exportAddr) {
          Interceptor.attach(exportAddr, {
            onEnter: function (args) {
              this.args = args;
              this.export = exportName;
            },
            onLeave: function (retval) {
              // Sample args[2..7] as potential jstrings; emit ONLY if one of
              // them contains a known identifier substring.
              for (var k = 2; k <= 7; k++) {
                try {
                  var s = jstringToString(this.args[k]);
                  if (!s || s.length === 0 || s.length > 4096) continue;
                  var hit = scanForKnownIds(s);
                  if (hit) {
                    emit("LIBCLIENT_KNOWN_ID_HIT", hit, {
                      export: this.export,
                      argIdx: k,
                      context: s.substring(0, 240)
                    });
                  }
                } catch (e) { /* swallow */ }
              }
            }
          });
        })(entry.name, entry.address);
        installed++;
      } catch (e) {
        // Some exports are not safe to hook (e.g. inline helpers); log + skip.
      }
    }
    emitInit("Network/messaging catch-all installed: " + installed + "/" + capped.length +
             " (filtered from " + watched.length + " matches across " + allExports.length + " exports)", true);
  }

  // ─── Wire-body capture: Java HTTP layer ─────────────────────────────────────
  // Three transports cover everything Snap uses end-to-end:
  //   (a) OkHttp        — most plain HTTP / Argos token requests
  //   (b) Cronet        — gRPC over HTTP/2 (signup-flow primary suspect)
  //   (c) HttpURLConn.  — fallback for libs bypassing the others
  // Each captures the bytes BEFORE TLS, scans for KNOWN_IDS, persists the
  // body as a blob if interesting, and emits a hit event if a substring
  // matches. Defensive: catches all exceptions; on parse failure, never
  // breaks Snap's actual upload.

  // Helper: scan a Java byte[] (jbyteArray) for KNOWN_IDS by streaming the
  // buffer into a JS string-of-bytes. Used by all three wire-body hooks.
  function scanJavaByteArrayForIds(jbyteArr) {
    if (!jbyteArr) return null;
    try {
      var len = jbyteArr.length;
      if (len <= 0 || len > 1024 * 1024) return null;
      // Build ASCII view as JS string. Non-printable bytes become NUL so
      // indexOf still works for our pure-ASCII-digit-and-+ identifiers.
      var view = new Uint8Array(len);
      for (var i = 0; i < len; i++) view[i] = jbyteArr[i] & 0xff;
      return scanBufferForKnownIds(view);
    } catch (e) {
      return null;
    }
  }

  // Helper: convert Java byte[] → ArrayBuffer for blob persistence.
  function javaByteArrayToBuffer(jbyteArr) {
    try {
      var len = jbyteArr.length;
      if (len <= 0 || len > 1024 * 1024) return null;
      var buf = new ArrayBuffer(len);
      var v = new Uint8Array(buf);
      for (var i = 0; i < len; i++) v[i] = jbyteArr[i] & 0xff;
      return { buf: buf, len: len };
    } catch (e) {
      return null;
    }
  }

  function installOkHttpFullBodyHook() {
    try {
      var RealInterceptorChain = Java.use("okhttp3.internal.http.RealInterceptorChain");
      var Buffer = Java.use("okio.Buffer");

      RealInterceptorChain.proceed.overload("okhttp3.Request").implementation = function (request) {
        try {
          var url = request.url().toString();
          var method = request.method();
          var bodyBytes = null;
          var bodyLen = 0;

          var rb = request.body();
          if (rb) {
            // Skip one-shot/duplex bodies (writeTo consumes them — would break upload).
            var safe = true;
            try {
              if (rb.isOneShot && rb.isOneShot()) safe = false;
              if (safe && rb.isDuplex && rb.isDuplex()) safe = false;
            } catch (eg) { /* old OkHttp */ }

            if (safe) {
              var buf = Buffer.$new();
              try {
                rb.writeTo(buf);
                // readByteArray returns Java byte[]; we keep it native to avoid
                // the UTF-8 decode round-trip that the original 400-char path used.
                bodyBytes = buf.readByteArray();
                bodyLen = bodyBytes.length;
              } catch (eW) {} finally {
                try { buf.close(); } catch (eC) {}
              }
            }
          }

          if (bodyBytes && bodyLen > 0) {
            var hit = scanJavaByteArrayForIds(bodyBytes);
            var blob = javaByteArrayToBuffer(bodyBytes);
            var meta = {
              url: url, method: method, length: bodyLen,
              head8: blob ? head8HexBytes(new Uint8Array(blob.buf)) : null
            };
            if (hit) {
              meta.knownIdHit = hit.hit;
              meta.knownIdOffset = hit.offset;
              emit("LIBCLIENT_KNOWN_ID_HIT", hit.hit, {
                source: "okhttp", url: url, method: method,
                length: bodyLen, offset: hit.offset, encoding: hit.encoding
              });
            }
            if (blob) {
              emitWithBlob("LIBCLIENT_OKHTTP_BODY", url, meta, blob.buf);
              try { dumpField16AndStructure(new Uint8Array(blob.buf), "okhttp_body", url); } catch (eF16) {}
            } else {
              emit("LIBCLIENT_OKHTTP_BODY", url, meta);
            }
          }
        } catch (eOuter) {}
        return this.proceed(request);
      };
      emitInit("OkHttp full-body capture (RealInterceptorChain.proceed)", true);
    } catch (e) {
      emitInit("OkHttp full-body capture (R8 likely stripped)", false, e);
    }
  }

  function installCronetUploadHook() {
    // org.chromium.net.UploadDataProviders.create(...) returns an
    // UploadDataProvider that wraps a static byte[] / ByteBuffer / File.
    // Snap calls one of these BEFORE handing the provider to UrlRequest.
    // We log the source bytes and pass through unchanged — zero risk.
    var hooked = 0;
    try {
      var UDP = Java.use("org.chromium.net.UploadDataProviders");

      // create(byte[])
      try {
        UDP.create.overload("[B").implementation = function (data) {
          try { handleCronetSource("byte[]", data, null); } catch (e) {}
          return UDP.create.overload("[B").call(UDP, data);
        };
        hooked++;
      } catch (e1) {}

      // create(byte[], int, int)
      try {
        UDP.create.overload("[B", "int", "int").implementation = function (data, off, len) {
          try {
            // Slice the relevant window if explicit offset+length given.
            handleCronetSource("byte[]+window", data, { offset: off, length: len });
          } catch (e) {}
          return UDP.create.overload("[B", "int", "int").call(UDP, data, off, len);
        };
        hooked++;
      } catch (e2) {}

      // create(ByteBuffer)
      try {
        UDP.create.overload("java.nio.ByteBuffer").implementation = function (bb) {
          try {
            // Read remaining() bytes via duplicate() so we don't perturb position.
            var dup = bb.duplicate();
            var rem = dup.remaining();
            if (rem > 0 && rem <= 1024 * 1024) {
              var BArrType = Java.use("[B");
              // Allocate a host byte[] and bulk-get
              var arr = Java.array("byte", new Array(rem).fill(0));
              dup.get(arr);
              handleCronetSource("ByteBuffer", arr, null);
            }
          } catch (e) {}
          return UDP.create.overload("java.nio.ByteBuffer").call(UDP, bb);
        };
        hooked++;
      } catch (e3) {}

      // create(File) — content unknown without reading; just log existence.
      try {
        UDP.create.overload("java.io.File").implementation = function (f) {
          try {
            emit("LIBCLIENT_CRONET_BODY", "<file source>", {
              source: "File", path: f ? String(f.getAbsolutePath()) : null,
              note: "streamed file upload — body not captured to avoid IO contention"
            });
          } catch (e) {}
          return UDP.create.overload("java.io.File").call(UDP, f);
        };
        hooked++;
      } catch (e4) {}

      emitInit("Cronet UploadDataProviders.create overloads hooked: " + hooked + "/4", true);
    } catch (e) {
      emitInit("Cronet UploadDataProviders not in classpath (Snap may use a private wrapper)", false, e);
    }

    // Defensive secondary path: hook UrlRequest$Builder.setUploadDataProvider
    // and log the provider class. If we see provider classes that aren't
    // routed through UploadDataProviders.create, we'll know to add a hook.
    try {
      var Builder = Java.use("org.chromium.net.UrlRequest$Builder");
      Builder.setUploadDataProvider.implementation = function (provider, executor) {
        try {
          var clsName = provider ? provider.getClass().getName() : "<null>";
          emit("LIBCLIENT_CRONET_BODY", "<provider attached>", {
            source: "setUploadDataProvider",
            providerClass: clsName,
            note: "passive observer — wraps nothing"
          });
        } catch (e) {}
        return this.setUploadDataProvider(provider, executor);
      };
      emitInit("Cronet UrlRequest$Builder.setUploadDataProvider observer", true);
    } catch (e) {
      // Different builder impls (CronetUrlRequest$Builder, etc.) — try alternates
      var alt = ["org.chromium.net.impl.UrlRequestBuilderImpl",
                 "org.chromium.net.impl.CronetUrlRequest$Builder"];
      for (var i = 0; i < alt.length; i++) {
        try {
          var B = Java.use(alt[i]);
          if (B && B.setUploadDataProvider) {
            B.setUploadDataProvider.implementation = function (provider, executor) {
              try {
                var clsName = provider ? provider.getClass().getName() : "<null>";
                emit("LIBCLIENT_CRONET_BODY", "<provider attached>", {
                  source: alt[i] + ".setUploadDataProvider",
                  providerClass: clsName
                });
              } catch (eI) {}
              return this.setUploadDataProvider(provider, executor);
            };
            emitInit("Cronet alt builder hooked: " + alt[i], true);
            break;
          }
        } catch (eAlt) {}
      }
    }
  }

  function handleCronetSource(label, jbyteArr, window) {
    var hit = scanJavaByteArrayForIds(jbyteArr);
    var blob = javaByteArrayToBuffer(jbyteArr);
    var meta = {
      source: label,
      length: blob ? blob.len : 0,
      head8: blob ? head8HexBytes(new Uint8Array(blob.buf)) : null
    };
    if (window) { meta.windowOffset = window.offset; meta.windowLength = window.length; }
    if (hit) {
      meta.knownIdHit = hit.hit;
      meta.knownIdOffset = hit.offset;
      emit("LIBCLIENT_KNOWN_ID_HIT", hit.hit, {
        source: "cronet", subSource: label,
        length: meta.length, offset: hit.offset, encoding: hit.encoding
      });
    }
    if (blob) {
      emitWithBlob("LIBCLIENT_CRONET_BODY", label, meta, blob.buf);
      try { dumpField16AndStructure(new Uint8Array(blob.buf), "cronet_body", label); } catch (eF16) {}
    } else {
      emit("LIBCLIENT_CRONET_BODY", label, meta);
    }
  }

  function installHttpUrlConnectionBodyHook() {
    // Wrap getOutputStream() so we can intercept writes before TLS.
    // Strategy: replace the returned OutputStream with a Java FilterOutputStream
    // subclass we register at runtime. Simpler alternative: hook the common
    // write paths on the concrete impl (sun.net.www.protocol.http.HttpURLConnection).
    // We use the simpler path — hook OutputStream.write([B,I,I) globally and
    // filter by caller class. This is broad but cheap and correct.
    try {
      // Hook the common HTTP body sink on Android: org.apache.harmony / OkHttp's
      // legacy underlying stream is `okhttp3.internal.connection.Exchange`. The
      // fallback for HttpsURLConnection is a sun.net.www stream chain; instead
      // of chasing each impl, we hook the high-level connect() AND set up an
      // outputStream observer if Snap actually opens one.
      var ConnCls = Java.use("java.net.HttpURLConnection");
      var origGetOS = ConnCls.getOutputStream;
      ConnCls.getOutputStream.implementation = function () {
        var os = origGetOS.call(this);
        try {
          var url = String(this.getURL());
          // Wrap once per OutputStream by installing a cumulative byte-collector
          // hook on its write(byte[],int,int) method via class-level hook.
          // Cheaper alternative: just emit URL on getOutputStream — we'll see
          // body via OkHttp/Cronet hooks if Snap routes that way. For pure
          // HttpURLConnection bodies (rare on modern Snap), this is the limit.
          emit("LIBCLIENT_HTTPURL_BODY", url, {
            note: "OutputStream returned — body capture deferred to Cronet/OkHttp layer"
          });
        } catch (e) {}
        return os;
      };
      emitInit("HttpURLConnection.getOutputStream observer", true);
    } catch (e) {
      emitInit("HttpURLConnection.getOutputStream observer", false, e);
    }
  }

  function installWireBodyHooks() {
    try { installOkHttpFullBodyHook(); }
    catch (e) { emitInit("installOkHttpFullBodyHook", false, e); }
    try { installCronetUploadHook(); }
    catch (e) { emitInit("installCronetUploadHook", false, e); }
    try { installHttpUrlConnectionBodyHook(); }
    catch (e) { emitInit("installHttpUrlConnectionBodyHook", false, e); }
  }

  // ─── Java-side gRPC body capture (safe replacement for JNI-level hooks) ────
  // The 4 *_native_submit JNI exports get called by Java wrappers in
  // `com.snapchat.client.network_api.NetworkApi$CppProxy` etc. Hooking the
  // Java side is safer because:
  //   (a) Method overloads are introspectable — we know which arg is byte[]
  //   (b) Java.use's wrapped objects are JNI-safe (no raw pointer casts)
  //   (c) `submit()` Java method takes a Request object; the byte[] body is a
  //       getter on it — we read it cleanly via Java reflection.
  //
  // ─── gRPC unary/streaming + duplex body capture (R8-static discovery) ─
  // Static analysis of base.apk via androguard 2026-04-30 confirmed that
  // Snap's signup body travels via UnifiedGrpcService.native_unaryCall,
  // NOT the network_api/network_manager submit path. R8 keeps these class
  // names because libclient.so JNI binds by exact name. Body type is
  // java.nio.ByteBuffer, NOT byte[], which is why every prior hook missed.
  //
  // See: D:/Claude Projects/OmniShield/dumps/snap_apk_v13.89.0.47/r8_wrappers_base.json
  function installGrpcUnaryHook() {
    var GRPC_TARGETS = [
      // [class, method, byteBufferArgIdx (0-based among args after `this`)]
      // Java.use('Cls').method.implementation gets all args incl. java args;
      // ByteBuffer is at arg index counting only the JS-visible ones.
      // For instance methods the `J` (long handle) is the FIRST visible arg.
      ["com.snapchat.client.grpc.UnifiedGrpcService$CppProxy",
       "native_unaryCall",
       /*endpointArg=*/1, /*bodyArg=*/2, "unary"],
      ["com.snapchat.client.grpc.UnifiedGrpcService$CppProxy",
       "native_serverStreamingCall",
       /*endpointArg=*/1, /*bodyArg=*/2, "server_streaming"],
      ["com.snapchat.client.grpc.ClientStreamSendHandler$CppProxy",
       "native_send",
       /*endpointArg=*/null, /*bodyArg=*/1, "client_streaming"],
      ["com.snapchat.client.duplex.DuplexClient$CppProxy",
       "native_send",
       /*endpointArg=*/1, /*bodyArg=*/2, "duplex_send"],
      // Response/incoming side — useful to correlate request to its response
      ["com.snapchat.client.grpc.UnaryEventHandler$CppProxy",
       "native_onEvent",
       /*endpointArg=*/null, /*bodyArg=*/1, "unary_response"],
      ["com.snapchat.client.duplex.MessageHandler$CppProxy",
       "native_onReceive",
       /*endpointArg=*/null, /*bodyArg=*/1, "duplex_recv"],
      ["com.snapchat.client.native_network_api.NativeNetworkRequestCallback$CppProxy",
       "native_onSucceeded",
       /*endpointArg=*/null, /*bodyArg=*/1, "native_network_success"]
    ];

    var hooked = 0;
    for (var t = 0; t < GRPC_TARGETS.length; t++) {
      var cname = GRPC_TARGETS[t][0];
      var mname = GRPC_TARGETS[t][1];
      var endpointArgIdx = GRPC_TARGETS[t][2];
      var bodyArgIdx = GRPC_TARGETS[t][3];
      var label = GRPC_TARGETS[t][4];
      try {
        var Cls = Java.use(cname);
        if (!Cls[mname]) {
          emitInit("gRPC: " + cname + "." + mname + " not present", false);
          continue;
        }
        var overloads = Cls[mname].overloads;
        for (var ov = 0; ov < overloads.length; ov++) {
          (function (cls, methodName, ovIdx, ep, body, lbl) {
            try {
              cls[methodName].overloads[ovIdx].implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                try {
                  var endpoint = (ep != null && args[ep]) ? String(args[ep]) : null;
                  var bb = (body != null) ? args[body] : null;
                  if (bb) {
                    var blob = javaByteBufferToBuffer(bb);
                    if (blob && blob.len > 0) {
                      var hit = scanBufferForKnownIds(new Uint8Array(blob.buf));
                      var meta = {
                        source: lbl,
                        endpoint: endpoint,
                        length: blob.len,
                        head8: head8HexBytes(new Uint8Array(blob.buf)),
                        method: methodName
                      };
                      if (hit) {
                        meta.knownIdHit = hit.hit;
                        emit("LIBCLIENT_KNOWN_ID_HIT", hit.hit, {
                          source: lbl, endpoint: endpoint,
                          length: blob.len, offset: hit.offset, encoding: hit.encoding
                        });
                      }
                      emitWithBlob("LIBCLIENT_GRPC_UNARY_BODY", endpoint || lbl, meta, blob.buf);
                      // Field 16 extractor — reuse the layer7 outer-body parser
                      try {
                        dumpField16AndStructure(new Uint8Array(blob.buf), lbl, endpoint);
                      } catch (eF16) {}
                    }
                  }
                } catch (eOuter) {}
                return cls[methodName].overloads[ovIdx].apply(this, args);
              };
              hooked++;
            } catch (eHook) {
              emitInit("gRPC hook " + cname + "." + methodName + "[" + ovIdx + "]", false, eHook);
            }
          })(Cls, mname, ov, endpointArgIdx, bodyArgIdx, label);
        }
        emitInit("gRPC " + label + ": " + cname + "." + mname + " (" + overloads.length + " overload)", true);
      } catch (e) {
        emitInit("gRPC class " + cname, false, e);
      }
    }
    emitInit("gRPC unary/streaming/duplex body capture: " + hooked + " hook(s) attached", true);
  }

  // Snap's R8 may rename these classes. We try the canonical names first,
  // fall back to enumerating loaded classes by Java.enumerateLoadedClassesSync
  // looking for `network_api` / `network_manager` substrings.
  function installNetworkApiJavaHook() {
    var CANDIDATES = [
      "com.snapchat.client.network_api.NetworkApi$CppProxy",
      "com.snapchat.client.network_manager.NetworkManager$CppProxy",
      "com.snapchat.client.native_network_api.NativeNetworkApi$CppProxy"
    ];
    var hooked = 0;
    for (var i = 0; i < CANDIDATES.length; i++) {
      var clsName = CANDIDATES[i];
      try {
        var Cls = Java.use(clsName);
        // Hook every overload of `submit` defensively. Most have signature
        // (Request, ResponseHandler) where Request has a body() / getBody()
        // accessor returning byte[].
        if (Cls.submit) {
          var overloads = Cls.submit.overloads;
          for (var j = 0; j < overloads.length; j++) {
            (function (cls, overloadIdx, methodName) {
              try {
                cls[methodName].overloads[overloadIdx].implementation = function () {
                  var args = Array.prototype.slice.call(arguments);
                  try {
                    // Try to extract byte[] body from any of the args.
                    for (var a = 0; a < args.length; a++) {
                      var argObj = args[a];
                      if (!argObj) continue;
                      // Skip primitives (number, string, boolean) — we only
                      // care about Request objects that have a body() getter.
                      if (typeof argObj === "number" || typeof argObj === "string" ||
                          typeof argObj === "boolean") continue;
                      // Try common body accessor names.
                      var body = null;
                      var ACCESSORS = ["getBody", "body", "getPayload", "payload",
                                       "getRequestBody", "requestBody", "getData", "data"];
                      for (var x = 0; x < ACCESSORS.length; x++) {
                        try {
                          if (argObj[ACCESSORS[x]]) {
                            body = argObj[ACCESSORS[x]]();
                            if (body) break;
                          }
                        } catch (eAcc) {}
                      }
                      if (body && body.length > 0 && body.length < 1024 * 1024) {
                        var hit = scanJavaByteArrayForIds(body);
                        var blob = javaByteArrayToBuffer(body);
                        var meta = {
                          source: "java_submit", class: clsName,
                          length: blob ? blob.len : 0,
                          head8: blob ? head8HexBytes(new Uint8Array(blob.buf)) : null
                        };
                        // Try to also get the URI / method if the Request exposes it
                        try {
                          var uri = null;
                          if (argObj.uri) uri = String(argObj.uri());
                          else if (argObj.getUri) uri = String(argObj.getUri());
                          else if (argObj.url) uri = String(argObj.url());
                          if (uri) meta.uri = uri;
                        } catch (eU) {}
                        if (hit) {
                          meta.knownIdHit = hit.hit;
                          emit("LIBCLIENT_KNOWN_ID_HIT", hit.hit, {
                            source: "java_submit", class: clsName,
                            length: meta.length, offset: hit.offset, encoding: hit.encoding,
                            uri: meta.uri || null
                          });
                        }
                        if (blob) {
                          emitWithBlob("LIBCLIENT_GRPC_SUBMIT", meta.uri || clsName, meta, blob.buf);
                          // TEST 1: parse outer-body protobuf, dump field 16 if present
                          try {
                            dumpField16AndStructure(new Uint8Array(blob.buf), "java_submit", meta.uri || clsName);
                          } catch (eF16) {}
                        } else {
                          emit("LIBCLIENT_GRPC_SUBMIT", meta.uri || clsName, meta);
                        }
                        break;
                      }
                    }
                  } catch (eOuter) {}
                  return cls[methodName].overloads[overloadIdx].apply(this, args);
                };
              } catch (eHook) {}
            })(Cls, j, "submit");
          }
          hooked++;
          emitInit("Java submit hook attached: " + clsName + " (" + overloads.length + " overloads)", true);
        }
      } catch (e) {
        // Class not in classpath — likely R8-renamed. Silent skip; we still
        // have OkHttp+Cronet+wire-body coverage upstream.
      }
    }
    if (hooked === 0) {
      emitInit("NetworkApi Java hooks: 0 classes found (likely R8-renamed; relying on Cronet UploadDataProviders + OkHttp)", false);
    } else {
      emitInit("NetworkApi Java hooks installed for " + hooked + " classes", true);
    }
  }

  // Read spoofed identifiers from Snap's runtime view. Snap sees what
  // OmniShield has spoofed via TelephonyManager / Build / Settings, so
  // calling those APIs from inside its process is the source of truth for
  // the current rotation's spoofed values. Adds substrings (incl. all
  // common phone variants: +CCNNN, CCNNN, NNN) to KNOWN_IDS in-place.
  function populateSpoofedIds() {
    var captured = [];
    function add(label, val) {
      if (!val || typeof val !== "string" || val.length === 0) return;
      if (KNOWN_IDS.indexOf(val) === -1) {
        KNOWN_IDS.push(val);
        captured.push(label + "=" + val);
      }
    }

    try {
      var ctx = Java.use("android.app.ActivityThread")
                    .currentApplication().getApplicationContext();
      var TM = Java.use("android.telephony.TelephonyManager");
      var tm = ctx.getSystemService("phone");
      if (tm) {
        try { add("IMSI", tm.getSubscriberId()); }
        catch (e) { /* SecurityException on A29+ without READ_PHONE_STATE — Snap has it though */ }
        try { add("ICCID", tm.getSimSerialNumber()); }
        catch (e) {}
        try {
          var phone = tm.getLine1Number();
          if (phone && phone.length > 0) {
            add("PHONE_FULL", phone);
            // Strip leading '+' and country code variants
            if (phone.charAt(0) === "+") {
              add("PHONE_NOPLUS", phone.substring(1));
              if (phone.length >= 4) add("PHONE_LOCAL", phone.substring(3));
            }
          }
        } catch (e) {}
      }

      try {
        var Build = Java.use("android.os.Build");
        add("SERIAL", Build.SERIAL.value);
      } catch (e) {}

      try {
        var Settings = Java.use("android.provider.Settings$Secure");
        var resolver = ctx.getContentResolver();
        var ANDROID_ID = Java.use("android.provider.Settings$Secure").ANDROID_ID.value;
        add("SSAID", Settings.getString(resolver, ANDROID_ID));
      } catch (e) {}

      try {
        var Adv = Java.use("com.google.android.gms.ads.identifier.AdvertisingIdClient");
        // GAID requires async call to GMS; skip if not in classpath of current app.
      } catch (e) {}
    } catch (e) {
      emitInit("populateSpoofedIds (Java)", false, e);
      return;
    }

    emit("__INIT__", "spoofed IDs captured at runtime: " + captured.join(", "));
    if (captured.length === 0) {
      emit("__INIT__", "WARNING: 0 spoofed IDs captured — TelephonyManager may not have READ_PHONE_STATE permission yet, or this is a non-Snap process. Real-ID detection still active.");
    }
  }

  // ─── AEAD dispatch hook — DISABLED 2026-04-29 (falsified) ───────────────────
  // The hypothesis that libclient.so+0xbb6220 is the active ChaCha20-Poly1305
  // seal function was FALSIFIED by live observation:
  //
  //   - 16-call burst in 31ms with byte-identical args (X0..X5) — a per-message
  //     seal would have distinct nonce/plaintext pointers per call.
  //   - Last call returns 0x0, the previous 15 return 0x1 — state-machine
  //     termination pattern (drain-while-1, exit-on-0), not a crypto seal.
  //   - The burst fires 23s AFTER ARGOS_CIPHERTEXT, not during the 198ms
  //     seal window observed by layer5 between PLAINTEXT and CIPHERTEXT.
  //
  // Re-interpretation of static evidence: the 2 rodata refs to "ChaCha20-Poly1305"
  // at offsets +9 ("Poly1305" substring) and +21 (4 bytes past null terminator)
  // are consistent with a hash-table / lookup-by-name pattern, NOT an AEAD
  // struct accessor (which would access the name field at offset 0).
  //
  // Architecturally, the active AEAD seal lives in libscplugin.so — Java method
  // iew.mpi.e is a JNI native binding into libscplugin (see layer5_argos.js
  // header). The 198ms window between layer5's PLAINTEXT and CIPHERTEXT events
  // is the seal executing inside that library, not libclient.so.
  //
  // Validation run: captures/aead_validation_20260429_150213.jsonl
  // Re-investigation route: Stalker.follow scoped to libscplugin.so during
  // iew.mpi.e (added in layer5_argos.js v2026-04-29).
  //
  // The function is kept as a stub — DO NOT re-enable without new static
  // evidence pointing at a different libclient.so offset.

  function installAeadDispatchHook() {
    emitInit("AEAD dispatch hook DISABLED — 0xbb6220 falsified 2026-04-29 " +
             "(burst pattern + 23s offset rule out per-message seal). Cipher " +
             "is in libscplugin.so, traced via layer5 Stalker scope.", true);
  }

  // ─── Native C++ unaryCall hook (PR-CppGate, 2026-04-30) ────────────────
  // Discovered via Ghidra/radare2 reversing of libclient.so (BuildID
  // de4118166321ca0df15c6ad7eba987c0):
  //   snap::grpc::UnifiedGrpcServiceImpl::unaryCall(
  //     std::string serviceMethod,
  //     std::vector<uint8_t> payload,
  //     sp<UnaryResponseHandler> handler,
  //     sp<GrpcEnvOptions> options
  //   ) at libclient.so + 0xbfb9ac
  //
  // Hooking the C++ method (not the JNI thunk at +0xbf2574) captures BOTH
  // Java callers AND C++ callers. Snap's signup is initiated from a
  // Composer C++ module that calls unaryCall directly on a C++ instance,
  // bypassing the Java method dispatch entirely — so the JNI thunk never
  // fires for signup but the C++ method does.
  //
  // AArch64 calling convention:
  //   X0 = this (UnifiedGrpcServiceImpl*)
  //   X1 = std::string* (endpoint URL — the gRPC service path)
  //   X2 = std::vector<uint8_t>* (payload — the body bytes incl. field 16)
  //   X3 = sp<UnaryResponseHandler>* (response handler)
  //   X4 = sp<GrpcEnvOptions>* (call options)
  var UNARYCALL_OFFSET = 0xbfb9ac;

  // libc++ alternate string layout (NDK r25+): bit 0 of byte 0 = is_long flag.
  //   SHORT (≤22 bytes): byte 0 = (size << 1) | 0; data starts at byte 1
  //   LONG: byte 0 LSB = 1; size at offset 8; data ptr at offset 16
  function readStdString(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
      var b0 = ptr.readU8();
      if ((b0 & 1) === 0) {
        var size = b0 >> 1;
        if (size > 22) return null;
        if (size === 0) return "";
        return ptr.add(1).readUtf8String(size);
      }
      var size64 = ptr.add(8).readU64();
      var size = size64.toNumber();
      if (size <= 0 || size > 64 * 1024) return null;
      var dataPtr = ptr.add(16).readPointer();
      if (dataPtr.isNull()) return null;
      return dataPtr.readUtf8String(size);
    } catch (e) { return null; }
  }

  // std::vector<T> layout (libc++): { T* begin; T* end; T* end_cap; }
  function readStdVectorU8(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
      var beginPtr = ptr.readPointer();
      var endPtr = ptr.add(8).readPointer();
      if (beginPtr.isNull() || endPtr.isNull()) return null;
      var size = endPtr.sub(beginPtr).toInt32();
      if (size <= 0 || size > 4 * 1024 * 1024) return null;
      var bytes = beginPtr.readByteArray(size);
      if (!bytes) return null;
      return { buf: bytes, len: size };
    } catch (e) { return null; }
  }

  function installCppUnaryCallHook() {
    if (!lib) {
      emitInit("CppUnaryCall: libclient.so not loaded", false);
      return;
    }
    var hookAddr;
    try {
      // The `var UNARYCALL_OFFSET` declaration at file scope ended up
      // undefined in Frida's runtime (verified via diagnostic). Cause not
      // pinned but hardcoding the literal everywhere bypasses the issue.
      hookAddr = lib.base.add(0xbfb9ac);
    } catch (eAddr) {
      emitInit("CppUnaryCall step1 lib.base.add", false, eAddr);
      return;
    }
    try {
      Interceptor.attach(hookAddr, {
        onEnter: function (args) {
          try {
            var endpointStrPtr = args[1];
            var bodyVecPtr = args[2];
            var endpoint = readStdString(endpointStrPtr);
            var blob = readStdVectorU8(bodyVecPtr);

            var meta = {
              source: "cpp_unary_call",
              addr: hookAddr.toString(),
              endpoint: endpoint || null,
              length: blob ? blob.len : 0,
              callerLR: this.returnAddress
                ? this.returnAddress.toString() : null
            };
            // Caller-module classification (helps distinguish C++ vs Java thunk callers)
            try {
              var range = Process.findModuleByAddress(this.returnAddress);
              if (range && range.name) {
                meta.callerModule = range.name;
                meta.callerOffset = this.returnAddress.sub(range.base).toString();
              }
            } catch (eR) {}

            if (blob && blob.len > 0) {
              var view = new Uint8Array(blob.buf);
              meta.head8 = head8HexBytes(view);
              var hit = scanBufferForKnownIds(view);
              if (hit) {
                meta.knownIdHit = hit.hit;
                emit("LIBCLIENT_KNOWN_ID_HIT", hit.hit, {
                  source: "cpp_unary_call",
                  endpoint: endpoint || null,
                  length: blob.len, offset: hit.offset, encoding: hit.encoding
                });
              }
              emitWithBlob("LIBCLIENT_CPP_UNARY_BODY", endpoint || "<no-endpoint>", meta, blob.buf);
              try {
                dumpField16AndStructure(view, "cpp_unary_call", endpoint);
              } catch (eF16) {}
            } else {
              emit("LIBCLIENT_CPP_UNARY_BODY", endpoint || "<no-endpoint>", meta);
            }
          } catch (eOuter) {
            // Never throw inside onEnter — Frida treats it as fatal hook failure
          }
        }
      });
      emitInit("CppUnaryCall: UnifiedGrpcServiceImpl::unaryCall hooked at libclient.so+0xbfb9ac (VA " + hookAddr.toString() + ")", true);
    } catch (e) {
      emitInit("CppUnaryCall hook attach", false, e);
    }
  }

  function installHooks() {
    emit("__INIT__", LIB_NAME + " base=" + lib.base + " size=" + lib.size +
         " — known-id watch list seeded with " + KNOWN_IDS.length + " real entries");

    // Native interceptor — no Java needed; install before Java.perform.
    try { installAeadDispatchHook(); }
    catch (e) { emitInit("installAeadDispatchHook", false, e); }

    // PR-CppGate: native C++ unaryCall hook for signup-from-Composer path.
    try { installCppUnaryCallHook(); }
    catch (e) { emitInit("installCppUnaryCallHook", false, e); }

    Java.perform(function () {
      try { populateSpoofedIds(); }
      catch (e) { emitInit("populateSpoofedIds", false, e); }
      try { installWireBodyHooks(); }
      catch (e) { emitInit("installWireBodyHooks", false, e); }
      try { installNetworkApiJavaHook(); }
      catch (e) { emitInit("installNetworkApiJavaHook", false, e); }
      // PR-FieldGate: real signup body sink, discovered via DEX static analysis 2026-04-30.
      // UnifiedGrpcService.native_unaryCall + DuplexClient.native_send + bidi + responses.
      try { installGrpcUnaryHook(); }
      catch (e) { emitInit("installGrpcUnaryHook", false, e); }
      // ─── DISABLED for crash containment (2026-04-29 v2 hot-patch) ──────────
      // The original JNI-level hooks bulk-Java.cast args[2..7] to jstring /
      // jbyteArray. For static native methods like *_native_submit(long handle,
      // byte[] body, ...) some args are JNI primitives (jlong) — casting a
      // primitive as a Java object corrupts JNI local refs and crashed Snap on
      // first Sign Up tap. Replaced by Java-side hook above (NetworkApi$CppProxy
      // is the Java caller of native_submit and is safe to wrap via Java.use).
      // Argos JNI hooks similarly disabled — Argos surface is already covered
      // by layer5_argos.js (Lfd0.getAttestationPayloadProto + Liew.mpi.e/f).
      // The catch-all 80-hook is also disabled — too high VM pressure during
      // signup-time burst, and the fired-when-hit value is duplicated by
      // installNetworkApiJavaHook + wire-body hooks.
      //   try { installArgosHooks(); }    catch(e) { ... }
      //   try { installGrpcSubmitHooks(); } catch(e) { ... }
      //   try { installCatchallHooks(); }  catch(e) { ... }
    });

    send({
      layer: "libclient",
      type: "__INIT__",
      value: "Layer 7 — full wire-body audit. Hooks: (1) OkHttp full-body, (2) Cronet UploadDataProvider, " +
             "(3) HttpURLConnection observer, (4) Argos JNI exports, (5) gRPC submit JNI, (6) network/messaging catch-all, " +
             "(7) AEAD dispatch sanity at libclient.so+0xbb6220 (cap=" + MAX_AEAD_DISPATCH + "). " +
             "Cap=" + MAX_EMITS + " events / " + MAX_BLOBS + " body blobs. KNOWN_ID watch list: " + KNOWN_IDS.length + " strings (real + spoofed via runtime read). " +
             "LIBCLIENT_KNOWN_ID_HIT on SPOOFED value (source=okhttp|cronet|grpc_body) = direct evidence the spoof reaches Snap's wire. " +
             "On REAL value = OmniShield regression. " +
             "Architectural finding (static, 2026-04-29): libclient.so has 9 gRPC services, NONE for signup. Signup-RPC body travels via Cronet/OkHttp Java layer.",
      caller: "",
      stack: [],
      ts: Date.now()
    });
  }
})();
