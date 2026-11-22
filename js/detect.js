"use strict";

/*
 * Detección de ataques / escaneos / bots.
 * Se expone como fábrica autocontenida para poder serializarla dentro del Web Worker.
 */
function createDetector() {
  const RE = {
    traversal: /\.\.[\/\\]|%2e%2e|\.\.%2f|\.\.%5c/,
    sqli: /(?:'|%27)\s*(?:or|and|--|;|\)|=)|union\s+(?:all\s+)?select|\bor\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema|;\s*drop\s+table|\bselect\b.+\bfrom\b/,
    xss: /<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<img[\s%]|%3cimg|<svg|%3csvg|alert\s*\(/,
    exploit: /\$\{jndi:|%24%7bjndi|\/etc\/passwd|cmd\.exe|powershell|\/bin\/(?:ba)?sh/,
    config: /\.env(?:\b|$)|\/\.git(?:\/|$)|web\.config|appsettings(?:\.[\w-]+)?\.json|wp-config|\.htaccess|\.htpasswd|\.ds_store/,
    wordpress: /wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php/,
    admin: /\/admin(?:istrator)?(?:\/|$|\.)/,
    db: /phpmyadmin|dbadmin|\/pma(?:\/|$)|\/mysql(?:\/|$)|adminer/,
    secTool: /sqlmap|nikto|nmap|acunetix|nessus|masscan|zgrab|dirbuster|gobuster|wpscan|nuclei/,
    bot: /bot|crawler|spider/,
    script: /curl|wget|python|go-http-client|libwww/,
  };

  function safeDecode(s) {
    try {
      return decodeURIComponent(s.replace(/\+/g, " "));
    } catch (e) {
      return s.replace(/\+/g, " ");
    }
  }

  function detectType(ua, uri, query) {
    const rawTarget = (uri + (query ? "?" + query : "")).toLowerCase();
    // Se revisa tanto el texto crudo como su versión decodificada
    const target = rawTarget + " " + safeDecode(rawTarget);
    ua = (ua || "").toLowerCase();

    // 1) Ataques sobre la URL (incluye query string)
    if (RE.traversal.test(target)) return "PATH TRAVERSAL";
    if (RE.exploit.test(target)) return "EXPLOIT ATTEMPT";
    if (RE.sqli.test(target)) return "SQL INJECTION";
    if (RE.xss.test(target)) return "XSS ATTACK";

    // 2) Herramientas de seguridad por User-Agent
    if (RE.secTool.test(ua)) return "SECURITY TOOL";

    // 3) Descubrimiento de archivos / paneles
    if (RE.config.test(target)) return "CONFIG SCAN";
    if (RE.wordpress.test(target)) return "WORDPRESS SCAN";
    if (RE.db.test(target)) return "DB SCAN";
    if (RE.admin.test(target)) return "ADMIN SCAN";

    // 4) Bots y automatización
    if (RE.bot.test(ua)) return "BOT";
    if (RE.script.test(ua)) return "SCRIPT";

    return "";
  }

  return {detectType, safeDecode};
}

if (typeof module !== "undefined") module.exports = {createDetector};
