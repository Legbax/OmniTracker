/**
 * Provoke layer for Phase 2B step 2: configure ferrite_bypass for bypass mode.
 */
(function () {
  globalThis.OT_FERRITE_MODE = "bypass";
  globalThis.OT_RUN_STALKER = true;
  try {
    send({ layer: "provoke", type: "PROVOKE_ARMED",
           value: "OT_FERRITE_MODE=bypass + OT_RUN_STALKER=true (Interceptor.replace +0x4fe4 with no-op stub; Stalker on Snap thread; expect Snap survives + events flow)",
           ts: Date.now() });
  } catch (e) {}
})();
