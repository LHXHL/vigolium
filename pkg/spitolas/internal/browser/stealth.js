// Stealth init script, registered with Page.addScriptToEvaluateOnNewDocument
// when spidering.stealth is on. It removes the automation markers a trivial bot
// wall checks for, so the crawl sees the page a normal browser sees. It is not
// an evasion feature: anything that fingerprints harder than this still sees
// an automated browser.
//
// Every patch is independent and wrapped in try/catch: a Chrome update that
// breaks one must not take the page (or the other patches) down with it. Each
// patch also checks the current value first and leaves a value that already
// looks like a normal browser alone.
//
// OPTS is replaced from Go (stealthScript) with a JSON object:
//   languages:      navigator.languages, derived from Accept-Language
//   headless:       the browser runs headless (gates the headless-only patches)
//   webglVendor:    UNMASKED_VENDOR_WEBGL to report instead of SwiftShader
//   webglRenderer:  UNMASKED_RENDERER_WEBGL to report instead of SwiftShader
(() => {
  'use strict';
  const opts = /*__VGO_STEALTH_OPTS__*/ {};
  const patch = (fn) => { try { fn(); } catch (e) { /* defensive: keep going */ } };

  // Functions the patches install, mapped to the source text a native
  // function of that name reports, so Function.prototype.toString does not
  // reveal them. Shared across every realm this script patches.
  const nativeText = new WeakMap();
  const asNative = (fn, name) => {
    nativeText.set(fn, 'function ' + name + '() { [native code] }');
    return fn;
  };
  const patchedRealms = new WeakSet();

  const defineGetter = (obj, prop, getter) => {
    const desc = Object.getOwnPropertyDescriptor(obj, prop);
    Object.defineProperty(obj, prop, {
      get: asNative(getter, 'get ' + prop),
      set: desc ? desc.set : undefined,
      configurable: true,
      enumerable: desc ? desc.enumerable : true,
    });
  };

  const apply = (win) => {
    const proto = win.Navigator && win.Navigator.prototype;
    if (!proto || patchedRealms.has(proto)) return;
    patchedRealms.add(proto);
    const nav = win.navigator;
    const isTop = (() => { try { return win === win.top; } catch (e) { return false; } })();

    // Function.prototype.toString: report patched functions as native.
    patch(() => {
      const FP = win.Function.prototype;
      const realToString = FP.toString;
      const toString = new Proxy(realToString, {
        apply(target, thisArg, args) {
          if (nativeText.has(thisArg)) return nativeText.get(thisArg);
          return Reflect.apply(target, thisArg, args);
        },
      });
      nativeText.set(toString, 'function toString() { [native code] }');
      Object.defineProperty(FP, 'toString', { value: toString, writable: true, configurable: true, enumerable: false });
    });

    // navigator.webdriver: a normal Chrome reports false, from the prototype
    // getter (an own property on navigator is itself a tell).
    patch(() => {
      if (nav.webdriver === false) return;
      defineGetter(proto, 'webdriver', () => false);
    });

    // navigator.languages: match the Accept-Language the browser sends.
    patch(() => {
      const langs = Array.isArray(opts.languages) ? opts.languages : [];
      if (!langs.length || JSON.stringify(Array.from(nav.languages || [])) === JSON.stringify(langs)) return;
      const frozen = Object.freeze(langs.slice());
      defineGetter(proto, 'languages', () => frozen);
    });

    // navigator.plugins / mimeTypes: an old headless build reports none; a
    // normal Chrome reports the built-in PDF viewer under five names.
    patch(() => {
      if (nav.plugins && nav.plugins.length > 0) return;
      if (!win.PluginArray || !win.Plugin || !win.MimeType || !win.MimeTypeArray) return;
      const mimeSpecs = [
        { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
        { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      ];
      const pluginNames = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'];
      const ro = (obj, values) => {
        for (const k of Object.keys(values)) {
          Object.defineProperty(obj, k, { value: values[k], enumerable: true, configurable: true });
        }
        return obj;
      };
      const indexed = (obj, items, keyOf) => {
        items.forEach((it, i) => {
          Object.defineProperty(obj, i, { value: it, enumerable: true, configurable: true });
          Object.defineProperty(obj, keyOf(it), { value: it, enumerable: false, configurable: true });
        });
        ro(obj, { length: items.length });
        Object.defineProperty(obj, 'item', { value: asNative(function item(i) { return items[i >>> 0] || null; }, 'item'), configurable: true });
        Object.defineProperty(obj, 'namedItem', { value: asNative(function namedItem(n) { return items.find((it) => keyOf(it) === n) || null; }, 'namedItem'), configurable: true });
        Object.defineProperty(obj, Symbol.iterator, { value: asNative(function values() { return items[Symbol.iterator](); }, 'values'), configurable: true });
        return obj;
      };
      const mimes = mimeSpecs.map((m) => ro(Object.create(win.MimeType.prototype), m));
      const plugins = pluginNames.map((name) => {
        const p = ro(Object.create(win.Plugin.prototype), { name, filename: 'internal-pdf-viewer', description: 'Portable Document Format' });
        return indexed(p, mimes, (m) => m.type);
      });
      mimes.forEach((m) => ro(m, { enabledPlugin: plugins[0] }));
      const pluginArray = indexed(Object.create(win.PluginArray.prototype), plugins, (p) => p.name);
      Object.defineProperty(pluginArray, 'refresh', { value: asNative(function refresh() {}, 'refresh'), configurable: true });
      const mimeArray = indexed(Object.create(win.MimeTypeArray.prototype), mimes, (m) => m.type);
      defineGetter(proto, 'plugins', () => pluginArray);
      defineGetter(proto, 'mimeTypes', () => mimeArray);
      if (nav.pdfViewerEnabled === false) defineGetter(proto, 'pdfViewerEnabled', () => true);
    });

    // window.chrome.runtime: present on a normal Chrome's secure pages.
    patch(() => {
      if (!win.isSecureContext) return;
      if (!win.chrome) {
        Object.defineProperty(win, 'chrome', { value: {}, writable: true, configurable: true, enumerable: true });
      }
      if ('runtime' in win.chrome) return;
      const fail = (name) => asNative(function () {
        throw new win.TypeError('Error in invocation of runtime.' + name + '(): chrome.runtime.' + name + '() called from a webpage must specify an Extension ID (string) for its first argument.');
      }, name);
      win.chrome.runtime = {
        OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' },
        OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' },
        PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformNaclArch: { ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformOs: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' },
        RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' },
        connect: fail('connect'),
        sendMessage: fail('sendMessage'),
        id: undefined,
      };
    });

    // permissions.query({name:'notifications'}) must agree with
    // Notification.permission (headless reports 'denied' vs 'prompt').
    patch(() => {
      if (!win.Permissions || !win.Notification || !win.PermissionStatus) return;
      const P = win.Permissions.prototype;
      const realQuery = P.query;
      const query = function query(desc) {
        if (desc && desc.name === 'notifications') {
          const perm = win.Notification.permission;
          const state = perm === 'default' ? 'prompt' : perm;
          const status = Object.setPrototypeOf({}, win.PermissionStatus.prototype);
          Object.defineProperty(status, 'state', { value: state, enumerable: true, configurable: true });
          Object.defineProperty(status, 'name', { value: 'notifications', enumerable: true, configurable: true });
          Object.defineProperty(status, 'onchange', { value: null, writable: true, enumerable: true, configurable: true });
          return win.Promise.resolve(status);
        }
        return realQuery.apply(this, arguments);
      };
      Object.defineProperty(P, 'query', { value: asNative(query, 'query'), writable: true, configurable: true, enumerable: true });
    });

    // WebGL vendor/renderer: headless renders with SwiftShader, which names
    // itself. Only a software renderer is replaced; a real GPU is left alone.
    patch(() => {
      if (!opts.headless || !opts.webglVendor || !opts.webglRenderer) return;
      const UNMASKED_VENDOR = 0x9245;
      const UNMASKED_RENDERER = 0x9246;
      const software = /SwiftShader|llvmpipe|Software/i;
      [win.WebGLRenderingContext, win.WebGL2RenderingContext].forEach((Ctx) => {
        if (!Ctx) return;
        const P = Ctx.prototype;
        const realGet = P.getParameter;
        const getParameter = function getParameter(pname) {
          const v = realGet.apply(this, arguments);
          if (pname === UNMASKED_RENDERER && typeof v === 'string' && software.test(v)) return opts.webglRenderer;
          if (pname === UNMASKED_VENDOR && typeof v === 'string') {
            let r = '';
            try { r = realGet.call(this, UNMASKED_RENDERER); } catch (e) { /* ignore */ }
            if (software.test(String(r))) return opts.webglVendor;
          }
          return v;
        };
        Object.defineProperty(P, 'getParameter', { value: asNative(getParameter, 'getParameter'), writable: true, configurable: true, enumerable: true });
      });
    });

    // outerWidth/outerHeight: headless has no window chrome, so outer == inner
    // (or 0). Top-level only: a frame's outer size is the top window's.
    patch(() => {
      if (!opts.headless || !isTop) return;
      if (win.outerWidth === 0 || win.outerWidth < win.innerWidth) {
        defineGetter(win, 'outerWidth', () => win.innerWidth);
      }
      if (win.outerHeight === 0 || win.outerHeight <= win.innerHeight) {
        defineGetter(win, 'outerHeight', () => win.innerHeight + 85);
      }
    });

    // iframe contentWindow: a same-origin frame's window (srcdoc, about:blank)
    // can be read before any init script ran in it. Patch it on first access.
    patch(() => {
      const P = win.HTMLIFrameElement && win.HTMLIFrameElement.prototype;
      const desc = P && Object.getOwnPropertyDescriptor(P, 'contentWindow');
      if (!desc || !desc.get) return;
      const realGet = desc.get;
      defineGetter(P, 'contentWindow', function () {
        const w = realGet.call(this);
        if (w) { try { apply(w); } catch (e) { /* cross-origin: nothing to patch */ } }
        return w;
      });
    });
  };

  try { apply(window); } catch (e) { /* never break the page */ }
})();
