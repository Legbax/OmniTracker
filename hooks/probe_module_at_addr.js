/**
 * One-shot: enumerate modules + identify the module containing
 * specific addresses (the SIGSEGV handler at 0x7d01c9708c).
 */
(function () {
  setTimeout(function () {
    var addrs = [
      "0x7bfc2da000",   // libferrite-launcher base (from ferrite_diag)
      "0x7bfc2defe4",   // SIGILL handler (libferrite-launcher+0x4fe4)
      "0x7d01c9708c",   // SIGSEGV handler (different module)
    ];
    var mods = Process.enumerateModules();
    var snapMods = [];
    for (var i = 0; i < mods.length; i++) {
      var m = mods[i];
      if (/snap|client|ferrite|kameleon|sigx|nloader|camplat|scplugin|libc|libssl|libcrypto|libart/i.test(m.name)) {
        snapMods.push({ name: m.name, base: m.base.toString(), end: m.base.add(m.size).toString(), size: m.size });
      }
    }
    send({ layer: "probe_module_at_addr", type: "MODULE_LIST", value: snapMods.length + " filtered", ts: Date.now(), modules: snapMods });
    for (var j = 0; j < addrs.length; j++) {
      var addr = ptr(addrs[j]);
      var hit = null;
      for (var i = 0; i < mods.length; i++) {
        var m = mods[i];
        if (addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0) {
          hit = { module: m.name, off: addr.sub(m.base).toString(), base: m.base.toString(), size: m.size, path: m.path };
          break;
        }
      }
      var sym = "?";
      try {
        var s = DebugSymbol.fromAddress(addr);
        if (s && s.name) sym = s.name + (s.moduleName ? ("@" + s.moduleName) : "");
      } catch (e) {}
      send({ layer: "probe_module_at_addr", type: "ADDR_LOOKUP", value: addrs[j] + " -> " + (hit ? hit.module + "+" + hit.off : "no module") + " sym=" + sym, ts: Date.now(), addr: addrs[j], hit: hit, sym: sym });
    }
  }, 200);
})();
