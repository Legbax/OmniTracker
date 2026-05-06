/**
 * probe_signup_outer.js — capture Snap's outgoing HTTP request bodies via
 * the network_manager Java→C++ bridge.
 *
 * Discovery: tools/snap_dex_mapper/dex_mapper.py produced
 * snap_v13.89.0.47_map.json with the JNI bridge classes + native method
 * descriptors. Names are stable for THIS APK build (versionCode 283422);
 * for future Snap updates, re-run the mapper and update the constants below.
 *
 * The path:
 *   1. Java code (Snap UI) → NetworkManager.submit(urlRequest, ...)
 *   2. NetworkManager$CppProxy.native_submit dispatches to libclient.so
 *   3. libclient.so queries UrlRequest.getPayloadDataRef() ← THE BODY
 *   4. libclient.so wraps in HTTP/2 frame + TLS encrypt + send
 *   5. UrlRequestCallback.native_onSuccess delivers response
 *
 * We hook the JAVA side of these (via Java.use().method.implementation),
 * which captures every request before TLS encryption. Captures:
 *   - URL, headers, request method
 *   - Payload body (ByteBuffer)
 *   - Response status + body (on success)
 *
 * Filter: emit ONLY when URL contains a signup-relevant marker, OR when
 * body length is non-trivial. Configurable via OT_SIGNUP_OUTER_FILTER.
 *
 * Output events (binary attachments where applicable):
 *   SIGNUP_REQUEST       — URL + method + headers + body bytes
 *   SIGNUP_RESPONSE      — HTTP status + body bytes from onSuccess
 *   SIGNUP_HOOK_ERROR    — diagnostic
 */
Java.perform(function () {

  // ─── config ─────────────────────────────────────────────────────────────
  var MAX_EMITS = 64;
  var BODY_PREVIEW = 64;   // bytes of head/tail in value field; full bytes in attachment

  // Class map — discovered by tools/snap_dex_mapper/dex_mapper.py for
  // Snap APK BuildID de4118166321ca0df15c6ad7eba987c0 (v13.89.0.47).
  var URL_REQUEST_CLS = "com.snapchat.client.network_manager.UrlRequest$CppProxy";
  var NETWORK_MANAGER_CLS = "com.snapchat.client.network_manager.NetworkManager$CppProxy";
  var URL_CB_CLS = "com.snapchat.client.network_manager.UrlRequestCallback$CppProxy";
  var GRPC_UNIFIED_CLS = "com.snapchat.client.grpc.UnifiedGrpcService$CppProxy";

  // Endpoint substring filter. Empty = capture all. Set to comma-separated
  // substrings to filter. Common: "RegistrationService,LoginService,Argos".
  var DEFAULT_FILTER = "";  // capture EVERYTHING by default
  var FILTER = (typeof OT_SIGNUP_OUTER_FILTER === "string") ? OT_SIGNUP_OUTER_FILTER : DEFAULT_FILTER;
  var FILTER_LIST = FILTER ? FILTER.split(",").map(function (s) { return s.trim(); }).filter(Boolean) : [];

  // ─── helpers ────────────────────────────────────────────────────────────
  var emittedCount = 0;

  function emit(type, value, extra, byteBuffer) {
    if (emittedCount >= MAX_EMITS) return;
    emittedCount++;
    var p = {
      layer: "signup_outer",
      type: type,
      value: value === null ? null : String(value),
      ts: Date.now()
    };
    if (extra) for (var k in extra) p[k] = extra[k];
    try {
      if (byteBuffer) send(p, byteBuffer); else send(p);
    } catch (e) {}
  }

  function emitInit(label, ok, err) {
    var p = {
      layer: "signup_outer",
      type: ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__",
      value: label, ts: Date.now()
    };
    if (err) p.err = String(err);
    try { send(p); } catch (e) {}
  }

  function urlMatchesFilter(url) {
    if (FILTER_LIST.length === 0) return true;
    if (!url) return false;
    var lo = String(url).toLowerCase();
    for (var i = 0; i < FILTER_LIST.length; i++) {
      if (lo.indexOf(FILTER_LIST[i].toLowerCase()) !== -1) return true;
    }
    return false;
  }

  // ByteBuffer to ArrayBuffer (for binary blob attachment).
  //
  // gRPC outgoing bodies arrive as ByteBuffer in one of two states:
  //   (A) "Read mode" — body already flipped: position=0, limit=N, capacity>=N
  //       remaining() = N. Bytes 0..N-1 are the body.
  //   (B) "Write mode" — body filled but not flipped: position=N, limit=capacity
  //       remaining() = capacity-N (= unused tail). Bytes 0..N-1 are the body.
  //
  // Some Snap endpoints pass mode (B): position equals body length, limit
  // is the full capacity. Reading remaining() returns 0 in mode (B) which
  // is WRONG — we'd miss the body entirely.
  //
  // Fix: read `min(position, limit)` as effective body end. Body is always
  // bytes [0 .. effective_end). This works for both modes:
  //   (A) min(0, N) = 0  → ALSO wrong. Need (A): use limit. (B): use position.
  //
  // Heuristic: read max(position, limit-position) bytes from offset 0. If
  // position > 0, it tells us the body length in mode (B). If limit > position
  // (mode A), use limit-position bytes from position. We capture both.
  function byteBufferToArrayBuffer(bb) {
    if (!bb) return { buf: null, len: 0, head: "", tail: "" };
    try {
      var pos = bb.position();
      var lim = bb.limit();
      var capacity = bb.capacity();
      var remaining = lim - pos;
      // Decide effective body length:
      //  - If remaining > 0, we're in read mode (A). Body is [pos, lim).
      //  - If remaining == 0 AND position > 0, we're in write mode (B).
      //    Body is [0, position).
      //  - Else: empty buffer (genuinely 0 bytes).
      var startOff, bodyLen;
      if (remaining > 0) {
        startOff = pos;
        bodyLen = remaining;
      } else if (pos > 0) {
        startOff = 0;
        bodyLen = pos;
      } else {
        return {
          buf: null, len: 0, head: "", tail: "",
          diag: "empty: pos=" + pos + " lim=" + lim + " cap=" + capacity
        };
      }
      // Cap at 2 MB
      var cap = Math.min(bodyLen, 2 * 1024 * 1024);
      var buf = new ArrayBuffer(cap);
      var view = new Uint8Array(buf);
      for (var i = 0; i < cap; i++) {
        view[i] = bb.get(startOff + i) & 0xff;
      }
      var hexHead = "", hexTail = "";
      var headN = Math.min(BODY_PREVIEW, cap);
      var tailN = (cap > BODY_PREVIEW * 2) ? Math.min(BODY_PREVIEW, cap) : 0;
      for (var j = 0; j < headN; j++) {
        var v = view[j];
        hexHead += (v < 16 ? "0" : "") + v.toString(16);
      }
      for (var k = cap - tailN; k < cap; k++) {
        var v2 = view[k];
        hexTail += (v2 < 16 ? "0" : "") + v2.toString(16);
      }
      return {
        buf: buf, len: bodyLen, head: hexHead, tail: hexTail, captured: cap,
        diag: "pos=" + pos + " lim=" + lim + " cap=" + capacity +
              " mode=" + (remaining > 0 ? "READ" : "WRITE") +
              " effective=[" + startOff + "," + (startOff + bodyLen) + ")"
      };
    } catch (e) {
      return { buf: null, len: 0, head: "", tail: "", error: String(e) };
    }
  }

  function javaByteArrayToArrayBuffer(jbytes) {
    if (!jbytes) return { buf: null, len: 0, head: "" };
    var len = jbytes.length;
    if (len <= 0) return { buf: null, len: 0, head: "" };
    var cap = Math.min(len, 2 * 1024 * 1024);
    var buf = new ArrayBuffer(cap);
    var view = new Uint8Array(buf);
    for (var i = 0; i < cap; i++) view[i] = jbytes[i] & 0xff;
    var hexHead = "";
    var headN = Math.min(BODY_PREVIEW, cap);
    for (var j = 0; j < headN; j++) {
      var v = view[j];
      hexHead += (v < 16 ? "0" : "") + v.toString(16);
    }
    return { buf: buf, len: len, head: hexHead, captured: cap };
  }

  // Render Java HashMap<String,String> as a JS object.
  function hashMapToObject(jmap) {
    if (!jmap) return null;
    var out = {};
    try {
      var iterator = jmap.entrySet().iterator();
      while (iterator.hasNext()) {
        var entry = iterator.next();
        var k = entry.getKey();
        var v = entry.getValue();
        out[String(k)] = (v == null) ? null : String(v);
        // Cap header count to avoid huge payloads
        if (Object.keys(out).length > 64) break;
      }
    } catch (e) { out["_err"] = String(e); }
    return out;
  }

  // ─── hook 1: UrlRequest$CppProxy.getPayloadDataRef ──────────────────────
  // Returns the body ByteBuffer for this request. Called by libclient.so
  // when it needs to read the outgoing payload. We capture URL+headers
  // by calling the other getters on `this`.
  try {
    var UrlRequest = Java.use(URL_REQUEST_CLS);
    var origGetPayloadDataRef = UrlRequest.getPayloadDataRef;
    UrlRequest.getPayloadDataRef.implementation = function () {
      var bb = origGetPayloadDataRef.call(this);
      try {
        var url = "";
        var method = "";
        var headersObj = null;
        try { url = String(this.getUrl()); } catch (e) {}
        try {
          var rm = this.getRequestMethod();
          if (rm) method = String(rm);
        } catch (e) {}
        try { headersObj = hashMapToObject(this.getHeaders()); } catch (e) {}

        if (urlMatchesFilter(url)) {
          var bb_info = byteBufferToArrayBuffer(bb);
          emit("SIGNUP_REQUEST",
               method + " " + url + " body=" + bb_info.len + "B",
               {
                 url: url,
                 method: method,
                 headers: headersObj,
                 body_length: bb_info.len,
                 body_captured_length: bb_info.captured || 0,
                 body_head_hex: bb_info.head || "",
                 body_tail_hex: bb_info.tail || "",
                 source: "UrlRequest.getPayloadDataRef"
               },
               bb_info.buf);
        }
      } catch (e) {
        emit("SIGNUP_HOOK_ERROR", "getPayloadDataRef inner: " + String(e));
      }
      return bb;
    };
    emitInit(URL_REQUEST_CLS + ".getPayloadDataRef", true);
  } catch (e) {
    emitInit(URL_REQUEST_CLS + ".getPayloadDataRef", false, e);
  }

  // ─── hook 2: NetworkManager$CppProxy.submit ────────────────────────────
  // Java-side entry point. Logs the request before any C++ processing.
  // The descriptor is:
  //   submit(UrlRequest, String, UrlRequestCallback, RequestContext, HashMap, RequestMediaType, Future)
  try {
    var NetworkManager = Java.use(NETWORK_MANAGER_CLS);
    // Pick whichever overload exists; Java.use returns a method that may
    // have multiple overloads. We attach to all to be resilient.
    var submitOverloads = NetworkManager.submit.overloads || [NetworkManager.submit];
    submitOverloads.forEach(function (overload) {
      var orig = overload;
      overload.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        try {
          var url = "(unknown)";
          var key = null;
          // Find UrlRequest in args (typed instance), get its URL
          for (var i = 0; i < args.length; i++) {
            var a = args[i];
            if (!a) continue;
            try {
              if (a.getUrl) {
                url = String(a.getUrl());
                break;
              }
            } catch (e) {}
          }
          // Sometimes the second arg is a String key
          for (var j = 0; j < args.length; j++) {
            if (typeof args[j] === "string") { key = args[j]; break; }
          }
          if (urlMatchesFilter(url)) {
            emit("SIGNUP_SUBMIT",
                 url + " key=" + (key || "?"),
                 { url: url, key: key, argCount: args.length,
                   source: "NetworkManager.submit" });
          }
        } catch (e) {
          emit("SIGNUP_HOOK_ERROR", "submit inner: " + String(e));
        }
        return orig.apply(this, args);
      };
    });
    emitInit(NETWORK_MANAGER_CLS + ".submit (" + submitOverloads.length + " overloads)", true);
  } catch (e) {
    emitInit(NETWORK_MANAGER_CLS + ".submit", false, e);
  }

  // ─── hook 3: UrlRequestCallback$CppProxy.onSuccess ─────────────────────
  // Response received. Per discovery, descriptor is something like:
  //   onSuccess(UrlRequest, UrlResponseInfo, ByteBuffer)
  // The third arg is the response body ByteBuffer.
  try {
    var UrlRequestCallback = Java.use(URL_CB_CLS);
    var origOnSuccess = UrlRequestCallback.onSuccess;
    UrlRequestCallback.onSuccess.implementation = function (request, info, body) {
      try {
        var url = "(unknown)";
        try { if (request && request.getUrl) url = String(request.getUrl()); } catch (e) {}
        var status = -1;
        try { if (info && info.getHttpStatusCode) status = info.getHttpStatusCode(); } catch (e) {}
        if (urlMatchesFilter(url)) {
          var bb_info = byteBufferToArrayBuffer(body);
          emit("SIGNUP_RESPONSE",
               url + " status=" + status + " body=" + bb_info.len + "B",
               {
                 url: url,
                 status: status,
                 body_length: bb_info.len,
                 body_captured_length: bb_info.captured || 0,
                 body_head_hex: bb_info.head || "",
                 body_tail_hex: bb_info.tail || "",
                 source: "UrlRequestCallback.onSuccess"
               },
               bb_info.buf);
        }
      } catch (e) {
        emit("SIGNUP_HOOK_ERROR", "onSuccess inner: " + String(e));
      }
      return origOnSuccess.apply(this, arguments);
    };
    emitInit(URL_CB_CLS + ".onSuccess", true);
  } catch (e) {
    emitInit(URL_CB_CLS + ".onSuccess", false, e);
  }

  // ─── hook 4: UnifiedGrpcService$CppProxy.unaryCall (Java side) ──────────
  // Frida wraps Java methods as Proxy objects, so `typeof a.position === "function"`
  // always returns false for ByteBuffer. Detect by TRYING the call instead.

  // ─── DirectByteBuffer extraction via Buffer field reflection ──────────
  // Frida's overload table for java.nio.Buffer/ByteBuffer is corrupted —
  // ALL `position()`/`limit()`/`capacity()` and `getMethod(name, Class[])`
  // resolve to int-arg overloads only. The no-arg getters are unreachable
  // through any method-call path Frida exposes.
  //
  // Bypass entirely: use Java reflection on the PRIVATE FIELDS of the
  // parent `java.nio.Buffer` class (`address`, `capacity`, `position`,
  // `limit`). `getDeclaredField(String)` has only ONE overload so no
  // ambiguity. Read native memory directly via `Memory.readByteArray`
  // at the buffer's `address + position` for `limit - position` bytes.
  //
  // SAFETY: only read when `limit > position` (== filled body). When
  // pos=0 lim=0 cap=N (Snap pre-allocated empty DirectByteBuffer not yet
  // filled), skip — reading capacity-bytes from address would hit a
  // PROT_NONE guard page → SIGSEGV in CPU-0 thread.
  var Buffer_addressField = null;
  var Buffer_capacityField = null;
  var Buffer_positionField = null;
  var Buffer_limitField = null;
  var Buffer_fieldNames = "";
  var bufferReflectionInitialized = false;
  var bufferReflectionInitErr = null;

  function initBufferReflection() {
    if (bufferReflectionInitialized) return;
    bufferReflectionInitialized = true;
    try {
      var BufferClass = Java.use("java.nio.Buffer").class;
      function getBufferField(name) {
        try {
          var direct = BufferClass.getDeclaredField(name);
          try { direct.setAccessible(true); } catch (e1) {}
          return direct;
        } catch (eDirect) {
          // Some ART/Frida combinations flake on getDeclaredField(String)
          // for core-oj classes. Enumerating and matching by name is stable.
          var fields = BufferClass.getDeclaredFields();
          for (var i = 0; i < fields.length; i++) {
            if (String(fields[i].getName()) === name) {
              try { fields[i].setAccessible(true); } catch (e2) {}
              return fields[i];
            }
          }
          throw eDirect;
        }
      }
      try {
        var listed = BufferClass.getDeclaredFields();
        var names = [];
        for (var n = 0; n < listed.length; n++) {
          names.push(String(listed[n].getName()));
        }
        Buffer_fieldNames = names.join(",");
      } catch (eList) {
        Buffer_fieldNames = "list-error:" + String(eList);
      }
      Buffer_addressField = getBufferField("address");
      try {
        Buffer_capacityField = getBufferField("capacity");
      } catch (eCap) {
        Buffer_capacityField = null;
      }
      Buffer_positionField = getBufferField("position");
      Buffer_limitField = getBufferField("limit");
      if (!Buffer_addressField || !Buffer_positionField || !Buffer_limitField) {
        bufferReflectionInitErr =
          "missing Buffer field(s): address=" + !!Buffer_addressField +
          " capacity=" + !!Buffer_capacityField +
          " position=" + !!Buffer_positionField +
          " limit=" + !!Buffer_limitField +
          " fields=[" + Buffer_fieldNames + "]";
      }
    } catch (e) {
      bufferReflectionInitErr = String(e) + " fields=[" + Buffer_fieldNames + "]";
    }
  }

  function jlongToPtrStr(jl) {
    if (jl === null || jl === undefined) return "0";
    if (typeof jl === "number") return jl.toString();
    if (typeof jl === "string") return jl;
    try {
      var s = jl.toString();
      if (s && s !== "[object Object]") return s;
    } catch (e) {}
    return String(jl);
  }

  function extractDirectBufferBody(bb) {
    if (!bb) return null;
    initBufferReflection();
    if (!Buffer_addressField || !Buffer_positionField || !Buffer_limitField) {
      return { len: 0, error: "buffer-reflection-init-failed: " + bufferReflectionInitErr };
    }
    try {
      var addrJL = Buffer_addressField.getLong(bb);
      var cap = null;
      if (Buffer_capacityField) {
        try { cap = Buffer_capacityField.getInt(bb); } catch (eCapRead) { cap = null; }
      }
      var pos = Buffer_positionField.getInt(bb);
      var lim = Buffer_limitField.getInt(bb);
      var addrStr = jlongToPtrStr(addrJL);

      // Effective body length:
      //  - readable (filled): lim > pos → bytes [pos, lim)
      //  - if pos > 0 and lim == cap (write-mode): bytes [0, pos)
      //  - else: empty (or capacity-only, not yet filled — UNSAFE to read)
      var startOff, bodyLen, mode;
      if (cap !== null && pos > 0 && lim === cap) {
        // write-mode: body filled but not flipped, [0, pos). Must come before
        // the lim > pos read-mode branch, otherwise we'd read the unused tail.
        startOff = 0;
        bodyLen = pos;
        mode = "write-mode";
      } else if (cap !== null && pos === 0 && lim === cap) {
        return {
          len: 0,
          diag: "BB-empty/ambiguous-write-buffer(safe-skip): addr=" + addrStr +
                " pos=" + pos + " lim=" + lim + " cap=" + cap
        };
      } else if (cap === null && pos === 0) {
        return {
          len: 0,
          diag: "BB-empty/ambiguous-no-cap(safe-skip): addr=" + addrStr +
                " pos=" + pos + " lim=" + lim + " cap=? fields=[" +
                Buffer_fieldNames + "]"
        };
      } else if (cap === null && pos > 0) {
        // Without capacity, DirectByteBuffer outgoing args are safest treated
        // as not-flipped write-mode. Read only [0,pos), never the tail.
        startOff = 0;
        bodyLen = pos;
        mode = "write-mode-no-cap";
      } else if (lim > pos) {
        startOff = pos;
        bodyLen = lim - pos;
        mode = "read-mode";
      } else {
        return {
          len: 0,
          diag: "BB-empty(safe-skip): addr=" + addrStr +
                " pos=" + pos + " lim=" + lim + " cap=" + cap
        };
      }

      // Cap at 2 MB
      var capRead = Math.min(bodyLen, 2 * 1024 * 1024);
      // For DirectByteBuffer, address is the base of native memory; for
      // HeapByteBuffer, address is 0 and bytes live in the 'hb' field.
      if (addrStr === "0") {
        return {
          len: bodyLen,
          diag: "HeapByteBuffer not supported here (address=0); skipping"
        };
      }

      // Read native memory directly. Memory.readByteArray catches faults
      // (returns null / throws on PROT_NONE pages).
      var nativePtr;
      try {
        nativePtr = ptr(addrStr);
        if (startOff > 0) nativePtr = nativePtr.add(startOff);
      } catch (e) {
        return {
          len: bodyLen,
          error: "ptr-conv: addrStr=" + addrStr + " err=" + String(e)
        };
      }
      var bytes = null;
      try {
        bytes = Memory.readByteArray(nativePtr, capRead);
      } catch (e) {
        return {
          len: bodyLen,
          error: "Memory.readByteArray@" + nativePtr + " len=" + capRead + ": " + String(e),
          diag: "addr=" + addrStr + " pos=" + pos + " lim=" + lim + " cap=" + cap + " mode=" + mode
        };
      }
      return {
        nativeBuf: bytes,   // ArrayBuffer (NOT a Java byte[])
        len: bodyLen,
        captured: capRead,
        pos: pos,
        lim: lim,
        nativeAddr: addrStr,
        diag: "REFLECT addr=" + addrStr + " pos=" + pos + " lim=" + lim +
              " cap=" + cap + " mode=" + mode
      };
    } catch (e) {
      return { len: 0, error: "reflection-read: " + String(e) };
    }
  }

  function tryCallByteBufferMethods(a) {
    // Returns { isBB: true, cls } or null
    // We don't read pos/lim/cap here — those go through the buggy method
    // binding. Just confirm the type via getClass(); body extraction uses
    // the no-cast duplicate/get pattern in extractDirectBufferBody().
    if (!a) return null;
    var className = "";
    try { className = String(a.getClass().getName()); } catch (e) { return null; }
    if (className.indexOf("ByteBuffer") === -1) return null;
    return { isBB: true, cls: className };
  }

  function tryByteArrayLength(a) {
    // Java byte[] arrays exposed by Frida have a `.length` numeric property
    if (!a) return -1;
    try {
      if (typeof a.length === "number") return a.length;
    } catch (e) {}
    return -1;
  }

  function describeArgType(a) {
    if (a === null || a === undefined) return "null";
    if (typeof a === "string") return "string";
    if (typeof a === "number") return "number";
    if (typeof a === "boolean") return "boolean";
    var bb = tryCallByteBufferMethods(a);
    if (bb) {
      return "ByteBuffer(pos=" + bb.pos + " lim=" + bb.lim + " cap=" + bb.cap + ")";
    }
    var arrLen = tryByteArrayLength(a);
    if (arrLen >= 0) return "byte[](len=" + arrLen + ")";
    try { return "obj:" + a.getClass().getName(); } catch (e) {}
    return "unknown";
  }

  // Compute hex head/tail from an ArrayBuffer/Uint8Array.
  function arrayBufferHexPreview(buf, captured) {
    if (!buf) return { head: "", tail: "" };
    var view = new Uint8Array(buf);
    var headN = Math.min(BODY_PREVIEW, captured);
    var tailN = (captured > BODY_PREVIEW * 2) ? Math.min(BODY_PREVIEW, captured) : 0;
    var hexHead = "", hexTail = "";
    for (var j = 0; j < headN; j++) {
      var v = view[j]; hexHead += (v < 16 ? "0" : "") + v.toString(16);
    }
    for (var k = captured - tailN; k < captured; k++) {
      var v2 = view[k]; hexTail += (v2 < 16 ? "0" : "") + v2.toString(16);
    }
    return { head: hexHead, tail: hexTail };
  }

  function readBodyFromArg(a) {
    if (!a) return { buf: null, len: 0, head: "", tail: "", diag: "null" };
    // Try as ByteBuffer first (Snap's primary type per arg_types diag).
    var bbResult = tryCallByteBufferMethods(a);
    if (bbResult && bbResult.isBB) {
      var ext = extractDirectBufferBody(a);
      if (ext && ext.nativeBuf && ext.captured > 0) {
        var preview = arrayBufferHexPreview(ext.nativeBuf, ext.captured);
        return {
          buf: ext.nativeBuf,    // ArrayBuffer from Memory.readByteArray
          len: ext.len,
          head: preview.head,
          tail: preview.tail,
          captured: ext.captured,
          diag: "BB cls=" + bbResult.cls + " " + (ext.diag || "")
        };
      }
      return {
        buf: null, len: ext ? ext.len : 0, head: "", tail: "",
        diag: "BB cls=" + bbResult.cls + " " +
              (ext && ext.diag ? ext.diag :
                "extract failed: " + (ext && ext.error || "?"))
      };
    }
    // Try as byte[]
    var arrLen = tryByteArrayLength(a);
    if (arrLen >= 0) {
      var info = javaByteArrayToArrayBuffer(a);
      info.diag = "byte[](" + arrLen + "B)";
      return info;
    }
    return { buf: null, len: 0, head: "", tail: "", diag: "neither ByteBuffer nor byte[]" };
  }

  try {
    var GrpcSvc = Java.use(GRPC_UNIFIED_CLS);
    var unaryOverloads = GrpcSvc.unaryCall.overloads || [GrpcSvc.unaryCall];
    unaryOverloads.forEach(function (overload) {
      var orig = overload;
      overload.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        try {
          var endpoint = (typeof args[0] === "string") ? args[0] : null;
          if (!endpoint) {
            for (var s = 0; s < args.length; s++) {
              if (typeof args[s] === "string") { endpoint = args[s]; break; }
            }
            endpoint = endpoint || "(?)";
          }

          // Build arg type table for diagnostic
          var argTypes = args.map(describeArgType);

          // Body is most likely arg[1] (after the endpoint string), but may
          // be at a different index. Try arg[1] first, then scan all.
          var bodyInfo = null;
          if (args.length > 1) {
            bodyInfo = readBodyFromArg(args[1]);
            if (bodyInfo.len > 0) {
              bodyInfo.bodyArgIdx = 1;
            } else {
              // Fallback: scan all args for first byte[] / ByteBuffer
              for (var i = 0; i < args.length; i++) {
                if (i === 0 && typeof args[i] === "string") continue;
                var ti = readBodyFromArg(args[i]);
                if (ti.len > 0) {
                  bodyInfo = ti;
                  bodyInfo.bodyArgIdx = i;
                  break;
                }
              }
            }
          }
          if (!bodyInfo) bodyInfo = { buf: null, len: 0, head: "", tail: "", diag: "no_body_arg" };

          if (urlMatchesFilter(endpoint)) {
            emit("SIGNUP_GRPC_UNARY",
                 endpoint + " body=" + bodyInfo.len + "B (arg" + (bodyInfo.bodyArgIdx === undefined ? "?" : bodyInfo.bodyArgIdx) + ")",
                 { endpoint: endpoint,
                   body_length: bodyInfo.len,
                   body_captured_length: bodyInfo.captured || 0,
                   body_head_hex: bodyInfo.head || "",
                   body_tail_hex: bodyInfo.tail || "",
                   body_diag: bodyInfo.diag || "",
                   body_arg_idx: bodyInfo.bodyArgIdx,
                   arg_types: argTypes,
                   source: "UnifiedGrpcService.unaryCall (Java)" },
                 bodyInfo.buf);
          }
        } catch (e) {
          emit("SIGNUP_HOOK_ERROR", "unaryCall inner: " + String(e));
        }
        return orig.apply(this, args);
      };
    });
    emitInit(GRPC_UNIFIED_CLS + ".unaryCall (" + unaryOverloads.length + " overloads)", true);
  } catch (e) {
    emitInit(GRPC_UNIFIED_CLS + ".unaryCall", false, e);
  }

  // ─── hook 5: DuplexClient$CppProxy.send ────────────────────────────────
  // Snap also uses DuplexClient for some bidi traffic (notifications, etc).
  // Descriptor: send(String, ByteBuffer, SendCallback, DispatchQueue) → void
  try {
    var DuplexClient = Java.use("com.snapchat.client.duplex.DuplexClient$CppProxy");
    if (DuplexClient && DuplexClient.send) {
      var sendOverloads = DuplexClient.send.overloads || [DuplexClient.send];
      sendOverloads.forEach(function (overload) {
        var orig = overload;
        overload.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          try {
            var endpoint = (typeof args[0] === "string") ? args[0] : "(?)";
            var bodyBB = null;
            for (var i = 0; i < args.length; i++) {
              var a = args[i];
              if (a && typeof a.position === "function" && typeof a.limit === "function") {
                bodyBB = a; break;
              }
            }
            if (urlMatchesFilter(endpoint)) {
              var info = bodyBB ? byteBufferToArrayBuffer(bodyBB)
                                : { buf: null, len: 0, head: "", tail: "" };
              emit("SIGNUP_DUPLEX_SEND",
                   endpoint + " body=" + info.len + "B",
                   { endpoint: endpoint, body_length: info.len,
                     body_captured_length: info.captured || 0,
                     body_head_hex: info.head || "",
                     source: "DuplexClient.send (Java)" },
                   info.buf);
            }
          } catch (e) {
            emit("SIGNUP_HOOK_ERROR", "duplex send inner: " + String(e));
          }
          return orig.apply(this, args);
        };
      });
      emitInit("DuplexClient.send (" + sendOverloads.length + " overloads)", true);
    }
  } catch (e) {
    emitInit("DuplexClient.send", false, e);
  }

  emit("__INIT__", "signup_outer probe armed (filter=" +
       (FILTER_LIST.length ? FILTER_LIST.join("|") : "<all>") +
       ", max_emits=" + MAX_EMITS + ")");
});
