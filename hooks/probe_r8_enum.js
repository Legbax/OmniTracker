// One-shot probe: enumerate Snap's R8-renamed network/HTTP classes.
//
// Goal: layer7_libclient.js's outer-body capture is dormant on Snap
// v13.89.0.47 because R8 stripped the canonical class names
// `okhttp3.internal.http.RealInterceptorChain` and
// `org.chromium.net.UploadDataProviders`. Find their renamed equivalents
// by structural signature so we can re-target the hooks.
//
// Strategy:
//   1. Java.enumerateMethods('*!intercept/i') — matches OkHttp Interceptor
//      implementations (intercept(Chain) -> Response)
//   2. Java.enumerateMethods('*!proceed/i') — matches OkHttp Chain
//      implementations (proceed(Request) -> Response)
//   3. Java.enumerateMethods('*!read/i') filtered structurally for Cronet
//      UploadDataProvider — read(UploadDataSink, ByteBuffer)
//   4. enumerateLoadedClassesSync substring scan as a backup for
//      partial-name-leak cases (R8 sometimes preserves substrings)
//
// Output: a single JSON dump per category. Operator greps it.

// Defer the heavy enumeration so script.load() can return immediately.
// Frida's RPC will time out if the script's top-level code blocks for >5s,
// and Java.enumerateMethods('*!intercept/i') over Snap's full dex easily
// exceeds that. Operator-side timeout in run_probe_r8.py is generous.
(function () {
  setTimeout(function () { Java.perform(function () {
    var report = {
      ts: Date.now(),
      intercept_owners: [],   // classes with method named "intercept"
      proceed_owners: [],     // classes with method named "proceed"
      uploadprovider_candidates: [],
      keyword_classes: [],    // any class whose NAME hints at network role
      enum_method_supported: true,
      enum_class_count: 0,
      errors: []
    };

    function progress(stage, extra) {
      try {
        var p = { stage: stage };
        if (extra) for (var k in extra) p[k] = extra[k];
        send({ layer: 'probe', type: 'R8_ENUM_PROGRESS', value: stage, data: p });
      } catch (eP) {}
    }
    progress('start');

    // ── (0) Classpath sanity precheck ────────────────────────────────
    // Validate Snap reached Landing/Main by probing well-known Snap classes
    // and a UI-stage class. If LandingPageActivity isn't loadable, the
    // process is in pre-UI anti-debug stall and the enumeration will give
    // false-negatives. Bail in that case.
    var sanity = {
      LandingPageActivity_loaded: false,
      ArgosClient_loaded: false,
      NetworkApi_loaded: false
    };
    try { Java.use('com.snapchat.android.LandingPageActivity'); sanity.LandingPageActivity_loaded = true; } catch (e) {}
    try { Java.use('com.snapchat.client.client_attestation.ArgosClient'); sanity.ArgosClient_loaded = true; } catch (e) {}
    try { Java.use('com.snapchat.client.network_api.NetworkApi$CppProxy'); sanity.NetworkApi_loaded = true; } catch (e) {}
    report.classpath_sanity = sanity;
    progress('classpath_sanity', sanity);
    // R8 renames the activity class even though the manifest string is
    // kept (dumpsys shows the manifest label). The real signal of a
    // fully-loaded Snap classpath is the @Keep'd Snap-internal classes
    // ArgosClient + NetworkApi$CppProxy — those CANNOT be R8-stripped
    // because libclient.so JNI binds to them by exact name.
    if (!sanity.ArgosClient_loaded || !sanity.NetworkApi_loaded) {
      report.errors.push('classpath_incomplete: ArgosClient or NetworkApi not loadable — process pre-init or anti-debug stall');
      send({ layer: 'probe', type: 'R8_ENUM_REPORT', value: 'aborted_incomplete_classpath', data: report });
      return;
    }

    // ── (1) intercept method owners ──────────────────────────────────
    progress('enumerate_intercept_begin');
    try {
      var iRes = Java.enumerateMethods('*!intercept/i');
      // Returns: [{ loader, classes: [{ name, methods: [...] }] }]
      for (var li = 0; li < iRes.length; li++) {
        var classes = iRes[li].classes || [];
        for (var ci = 0; ci < classes.length; ci++) {
          report.intercept_owners.push({
            name: classes[ci].name,
            methods: classes[ci].methods
          });
        }
      }
    } catch (e) {
      report.errors.push('enumerateMethods(intercept): ' + String(e));
      report.enum_method_supported = false;
    }

    progress('enumerate_intercept_done', { count: report.intercept_owners.length });
    // Emit a partial report after step 1 so the runner has data even on timeout
    send({ layer: 'probe', type: 'R8_ENUM_PARTIAL', value: 'after_step1', data: report });

    // ── (2) proceed method owners ────────────────────────────────────
    progress('enumerate_proceed_begin');
    try {
      var pRes = Java.enumerateMethods('*!proceed/i');
      for (var li = 0; li < pRes.length; li++) {
        var classes = pRes[li].classes || [];
        for (var ci = 0; ci < classes.length; ci++) {
          report.proceed_owners.push({
            name: classes[ci].name,
            methods: classes[ci].methods
          });
        }
      }
    } catch (e) {
      report.errors.push('enumerateMethods(proceed): ' + String(e));
    }

    progress('enumerate_proceed_done', { count: report.proceed_owners.length });
    send({ layer: 'probe', type: 'R8_ENUM_PARTIAL', value: 'after_step2', data: report });

    // ── (3) UploadDataProvider candidates ────────────────────────────
    progress('enumerate_read_begin');
    // Cronet's UploadDataProvider is an abstract class with these abstract
    // methods (all 3 must be present in a concrete subclass):
    //   long getLength()
    //   void read(UploadDataSink sink, ByteBuffer buffer)
    //   void rewind(UploadDataSink sink)
    // Java.enumerateMethods('*!read/i') returns thousands of hits. We pull
    // those, then for each distinct class try to reflect getLength + rewind
    // to confirm.
    var readClasses = {};
    try {
      var rRes = Java.enumerateMethods('*!read/i');
      for (var li = 0; li < rRes.length; li++) {
        var classes = rRes[li].classes || [];
        for (var ci = 0; ci < classes.length; ci++) {
          readClasses[classes[ci].name] = classes[ci].methods;
        }
      }
    } catch (e) {
      report.errors.push('enumerateMethods(read): ' + String(e));
    }

    var classNames = Object.keys(readClasses);
    progress('read_classes_collected', { count: classNames.length });
    // R8 also renames param types. Don't gate on param-name substring;
    // use the trinity (read/2, getLength/0, rewind/1) as the fingerprint.
    // Cronet's UploadDataProvider is the only well-known abstract class
    // requiring exactly that combination.
    var processed = 0;
    for (var i = 0; i < classNames.length; i++) {
      var cname = classNames[i];
      if (cname.indexOf('java.') === 0 || cname.indexOf('javax.') === 0 ||
          cname.indexOf('android.') === 0 || cname.indexOf('com.android.') === 0 ||
          cname.indexOf('libcore.') === 0 || cname.indexOf('sun.') === 0 ||
          cname.indexOf('dalvik.') === 0 || cname.indexOf('kotlin.') === 0 ||
          cname.indexOf('kotlinx.') === 0) continue;
      try {
        var Cls = Java.use(cname);
        var hasGetLength = false, hasRead2 = false, hasRewind1 = false;
        var meths = Cls.class.getDeclaredMethods();
        var sigs = [];
        for (var m = 0; m < meths.length; m++) {
          var mname = meths[m].getName();
          var ptlen = meths[m].getParameterTypes().length;
          var sig = mname + '(' + ptlen + ')';
          sigs.push(sig);
          if (mname === 'getLength' && ptlen === 0) hasGetLength = true;
          if (mname === 'read' && ptlen === 2) hasRead2 = true;
          if (mname === 'rewind' && ptlen === 1) hasRewind1 = true;
        }
        if (hasRead2 && hasGetLength && hasRewind1) {
          report.uploadprovider_candidates.push({
            name: cname,
            confidence: 'HIGH',
            method_sigs: sigs.slice(0, 40)
          });
        } else if (hasRead2 && (hasGetLength || hasRewind1)) {
          report.uploadprovider_candidates.push({
            name: cname,
            confidence: 'MEDIUM',
            method_sigs: sigs.slice(0, 40)
          });
        }
        processed++;
        if (processed % 50 === 0) progress('read_class_iter', { processed: processed, total: classNames.length });
      } catch (eUse) {}
    }

    progress('uploadprovider_filter_done', { candidates: report.uploadprovider_candidates.length });
    send({ layer: 'probe', type: 'R8_ENUM_PARTIAL', value: 'after_step3', data: report });

    // ── (3.5) Interface-relationship scan (R8 can't rename external ifs) ──
    // OkHttp Interceptor and the AOSP-fork variants are EXTERNAL interfaces;
    // R8 preserves "implements" relationships even though it renames methods
    // and class names. Enumerate Snap-internal classes (non-platform names)
    // that implement any of these interfaces. These are the renamed
    // interceptors we lost in step 1/2.
    progress('iface_scan_begin');
    var IFACE_TARGETS = [
      'com.android.okhttp.Interceptor',
      'com.android.okhttp.internal.http.HttpEngine$NetworkInterceptorChain',
      'okhttp3.Interceptor',
      'okhttp3.Interceptor$Chain',
      'org.chromium.net.UploadDataProvider'
    ];
    report.iface_implementors = {};
    for (var ti = 0; ti < IFACE_TARGETS.length; ti++) {
      report.iface_implementors[IFACE_TARGETS[ti]] = [];
    }
    var iface_processed = 0;
    var IFACE_DEADLINE_MS = 30000;
    var ifaceStartedAt = Date.now();
    // Reuse the read-step's classNames as a sample of "non-system" classes;
    // it's already a dedup'd set of 250-300 Snap-internal candidates.
    var sampleSet = classNames; // from step 3 above
    // Add proceed_owners/intercept_owners class names too (cheap boost)
    var addClassesFromList = function (list) {
      for (var x = 0; x < list.length; x++) {
        if (sampleSet.indexOf(list[x].name) === -1) sampleSet.push(list[x].name);
      }
    };
    addClassesFromList(report.intercept_owners);
    addClassesFromList(report.proceed_owners);

    for (var i = 0; i < sampleSet.length; i++) {
      if (Date.now() - ifaceStartedAt > IFACE_DEADLINE_MS) {
        progress('iface_scan_truncated', { processed: i, total: sampleSet.length });
        break;
      }
      var cname = sampleSet[i];
      if (cname.indexOf('java.') === 0 || cname.indexOf('javax.') === 0 ||
          cname.indexOf('android.') === 0 || cname.indexOf('com.android.') === 0 ||
          cname.indexOf('libcore.') === 0 || cname.indexOf('sun.') === 0 ||
          cname.indexOf('dalvik.') === 0 || cname.indexOf('org.chromium.') === 0) continue;
      try {
        var Cls = Java.use(cname);
        var clsObj = Cls.class;
        // walk superclass + interfaces chain
        var ancestors = [];
        var current = clsObj;
        var depth = 0;
        while (current && depth < 6) {
          ancestors.push(current.getName());
          var ifs = current.getInterfaces();
          for (var fi = 0; fi < ifs.length; fi++) ancestors.push(ifs[fi].getName());
          current = current.getSuperclass();
          depth++;
        }
        for (var ti2 = 0; ti2 < IFACE_TARGETS.length; ti2++) {
          var target = IFACE_TARGETS[ti2];
          if (ancestors.indexOf(target) !== -1) {
            report.iface_implementors[target].push(cname);
          }
        }
        iface_processed++;
        if (iface_processed % 50 === 0) {
          progress('iface_class_iter', { processed: iface_processed, total: sampleSet.length });
        }
      } catch (eIf) {}
    }
    var ifaceTotal = 0;
    for (var k in report.iface_implementors) ifaceTotal += report.iface_implementors[k].length;
    progress('iface_scan_done', { total_implementors: ifaceTotal });
    send({ layer: 'probe', type: 'R8_ENUM_PARTIAL', value: 'after_step3.5', data: report });

    // ── (4) keyword class-name scan (async, capped) ─────────────────
    // Java.enumerateLoadedClassesSync blocks for 30s+ on Snap's full dex.
    // Use the async streaming variant with an early break at MAX_HITS.
    progress('keyword_scan_begin');
    var KW = /(?:Cronet|cronet|OkHttp|okhttp|Interceptor|interceptor|UploadData|RealInterceptor|HttpEngine|NetworkRequest|Chain|Client_)/;
    var MAX_HITS = 200;
    var KEYWORD_DEADLINE_MS = 25000;
    var startedAt = Date.now();
    var classCount = 0;
    var hits = [];
    var stopRequested = false;
    try {
      Java.enumerateLoadedClasses({
        onMatch: function (nm) {
          if (stopRequested) return 'stop';
          classCount++;
          if (hits.length >= MAX_HITS) { stopRequested = true; return 'stop'; }
          if (Date.now() - startedAt > KEYWORD_DEADLINE_MS) { stopRequested = true; return 'stop'; }
          if (!KW.test(nm)) return;
          if (nm.indexOf('android.') === 0 || nm.indexOf('com.android.') === 0 ||
              nm.indexOf('java.') === 0 || nm.indexOf('javax.') === 0 ||
              nm.indexOf('libcore.') === 0 || nm.indexOf('dalvik.') === 0 ||
              nm.indexOf('sun.') === 0) return;
          hits.push(nm);
        },
        onComplete: function () {
          report.keyword_classes = hits;
          report.enum_class_count = classCount;
          progress('keyword_scan_done', {
            count: hits.length, total_classes: classCount,
            elapsed_ms: Date.now() - startedAt
          });
          send({ layer: 'probe', type: 'R8_ENUM_REPORT', value: 'ok', data: report });
        }
      });
    } catch (e) {
      report.errors.push('enumerateLoadedClasses(async): ' + String(e));
      // Send what we have anyway
      progress('keyword_scan_failed', { err: String(e) });
      send({ layer: 'probe', type: 'R8_ENUM_REPORT', value: 'partial', data: report });
      return;
    }
    return; // Final REPORT is emitted inside onComplete above
  }); }, 50);
})();
