/**
 * Provoke layer: schedule a self-inflicted SIGSEGV in Snap process.
 *
 * Sets globalThis.OT_SELF_CRASH = "<seconds>" so ferrite_diag.maybeScheduleSelfCrash()
 * fires N seconds after probe init. This produces a deterministic SIGSEGV at fault
 * address 0x1, which ferrite's signal handler catches → fork+exec libferrite-tracer.so
 * → tgkill re-raise. Probe's hooks capture the entire pipeline.
 *
 * Load order: must come BEFORE ferrite_diag in --layers.
 *   --layers provoke_self_crash,ferrite_diag
 * The combined-load path in android_monitor.py kicks in automatically when any
 * layer name starts with "provoke_".
 */
(function () {
  globalThis.OT_SELF_CRASH = "8:11";   // raise SIGSEGV 8s after probe init
  try {
    send({
      layer: "provoke", type: "PROVOKE_ARMED",
      value: "OT_SELF_CRASH = 8 (Snap will SIGSEGV at fault addr 0x1 in ~8s post-init)",
      ts: Date.now()
    });
  } catch (e) {}
})();
