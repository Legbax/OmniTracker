/**
 * Provoke layer: enable syscall(2) wrapper hook BEFORE layer2_native loads.
 *
 * layer2_native.js gates `_OT_SYSCALL_HOOK` to false by default (documented as
 * "libferrite anti-tamper trigger"). To capture the ferrite death certificate
 * (Strategy B Phase 2A), we deliberately enable it here so layer2_native sees
 * `globalThis._OT_SYSCALL_HOOK === true` at evaluation time.
 *
 * Load order matters: this file MUST be in the --layers list before `native`.
 *   --layers provoke_syscall,ferrite_diag,native
 */
(function () {
  globalThis._OT_SYSCALL_HOOK = true;
  try {
    send({
      layer: "provoke", type: "PROVOKE_ARMED",
      value: "_OT_SYSCALL_HOOK = true (will trigger ferrite SIGSEGV via getpid syscall burst)",
      ts: Date.now()
    });
  } catch (e) {}
})();
