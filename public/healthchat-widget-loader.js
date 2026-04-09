/**
 * HealthChat embed loader (no dependencies). Injects an iframe whose document loads the widget bundle.
 *
 * Usage:
 * <script
 *   src="https://your-cdn/healthchat-widget-loader.js"
 *   data-widget-src="https://your-cdn/widget.html"
 *   data-config='{"tenantId":"…","lockTenant":true,"position":"right","panelWidth":400}'
 *   async
 * ></script>
 *
 * Or point data-config-id at a <script type="application/json" id="hc-cfg">{ ... }</script>
 */
(function () {
  'use strict';

  function attr(el, name) {
    return (el.getAttribute(name) || '').trim();
  }

  function parseConfig(script) {
    var raw = attr(script, 'data-config');
    if (raw) {
      try {
        return JSON.parse(raw);
      } catch (e) {
        console.warn('[HealthChat] Invalid data-config JSON', e);
      }
    }
    var id = attr(script, 'data-config-id');
    if (id) {
      var el = document.getElementById(id);
      if (el && el.textContent) {
        try {
          return JSON.parse(el.textContent);
        } catch (e2) {
          console.warn('[HealthChat] Invalid JSON in #' + id, e2);
        }
      }
    }
    return {};
  }

  function appendQuery(base, config) {
    var keys = [
      'tenantId',
      'lockTenant',
      'hideTenantField',
      'position',
      'offsetBottom',
      'offsetSide',
      'launcherSize',
      'launcherIconUrl',
      'launcherAriaLabel',
      'defaultOpen',
      'panelWidth',
      'panelHeight',
      'panelMaxWidth',
      'panelMaxHeight',
      'panelBorderRadius',
      'panelBoxShadow',
      'closeOnEscape',
      'closeOnClickOutside'
    ];
    var u = new URL(base, window.location.href);
    var params = new URLSearchParams(u.search);
    keys.forEach(function (k) {
      if (!Object.prototype.hasOwnProperty.call(config, k)) {
        return;
      }
      var v = config[k];
      if (v === undefined || v === null || v === '') {
        return;
      }
      params.set(k, typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v));
    });
    u.search = params.toString();
    return u.toString();
  }

  /**
   * Iframe outer size in host pixels. Keep in sync with getWidgetEmbedIframeSizePx in
   * src/utils/widget-embed-resize.utils.ts (widget posts resize when panel opens/closes).
   */
  function iframeBox(config, panelOpen) {
    var w = Number(config.panelWidth) || 380;
    var h = Number(config.panelHeight) || 560;
    var ls = Number(config.launcherSize) || 56;
    var ob = Number(config.offsetBottom) || 24;
    var os = Number(config.offsetSide) || 24;
    var z = Number(config.zIndex) || 2147483000;
    var pos = config.position === 'left' ? 'left' : 'right';
    var vw = window.innerWidth - 16;
    var vh = window.innerHeight - 16;
    var iw;
    var ih;
    if (panelOpen) {
      iw = Math.min(w + 40, vw);
      ih = Math.min(h + ls + 56, vh);
    } else {
      iw = Math.min(ls + os + 40, vw);
      ih = Math.min(ls + ob + 40, vh);
    }
    return (
      'position:fixed;border:0;background:transparent;' +
      'width:' +
      iw +
      'px;height:' +
      ih +
      'px;bottom:' +
      (ob - 4) +
      'px;' +
      pos +
      ':' +
      (os - 4) +
      'px;z-index:' +
      z +
      ';overflow:hidden;pointer-events:auto;'
    );
  }

  function configDefaultOpen(config) {
    var v = config.defaultOpen;
    return v === true || v === 'true';
  }

  function run() {
    var scripts = document.getElementsByTagName('script');
    var s = null;
    for (var i = 0; i < scripts.length; i++) {
      if (scripts[i].src && scripts[i].src.indexOf('healthchat-widget-loader') !== -1) {
        s = scripts[i];
        break;
      }
    }
    if (!s) {
      return;
    }
    var base = attr(s, 'data-widget-src');
    if (!base) {
      console.error('[HealthChat] Loader requires data-widget-src (URL to widget.html)');
      return;
    }
    var config = parseConfig(s);
    var iframe = document.createElement('iframe');
    iframe.src = appendQuery(base, config);
    iframe.title = config.launcherAriaLabel || 'HealthChat';
    iframe.setAttribute('allow', 'microphone');
    var panelOpen = configDefaultOpen(config);
    iframe.style.cssText = iframeBox(config, panelOpen);
    document.body.appendChild(iframe);

    window.addEventListener('message', function (ev) {
      var d = ev.data;
      if (ev.source !== iframe.contentWindow) {
        return;
      }
      if (!d || d.source !== 'healthchat-widget' || d.type !== 'resize') {
        return;
      }
      var nw = Number(d.width);
      var nh = Number(d.height);
      if (!nw || !nh || nw < 32 || nh < 32) {
        return;
      }
      iframe.style.width = nw + 'px';
      iframe.style.height = nh + 'px';
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
