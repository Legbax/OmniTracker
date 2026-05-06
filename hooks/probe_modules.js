// One-shot probe: enumerate all loaded modules in the Snap process.
// Used to verify whether libkameleon.so is in the address space.
(function () {
  setTimeout(function () {
    var mods = Process.enumerateModules();
    var report = {
      total: mods.length,
      filtered: []
    };
    for (var i = 0; i < mods.length; i++) {
      var m = mods[i];
      // Filter for Snap-related, known-suspicious, and crypto-related libs
      if (/scplugin|kameleon|ferrite|client|crypto|ssl|nloader|sigx|camplat|snap/i.test(m.name)) {
        report.filtered.push({
          name: m.name,
          base: m.base.toString(),
          size: m.size,
          path: m.path
        });
      }
    }
    send({ layer: "probe", type: "MODULE_ENUM", value: "ok", data: report });
  }, 100);
})();
