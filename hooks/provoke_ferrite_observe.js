/**
 * Provoke layer for Phase 2B step 1: configure ferrite_bypass for observe mode
 * with Stalker trigger enabled.
 */
(function () {
  globalThis.OT_FERRITE_MODE = "observe";
  globalThis.OT_RUN_STALKER = true;
  try {
    send({ layer: "provoke", type: "PROVOKE_ARMED",
           value: "OT_FERRITE_MODE=observe + OT_RUN_STALKER=true (Stalker on Snap thread expected to die — capture +0x4fe4 and +0x50d8 chain)",
           ts: Date.now() });
  } catch (e) {}
})();
