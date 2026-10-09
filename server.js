const express = require('express');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_REDIRECTS = 6;
const MAX_BYTES = 30 * 1024 * 1024;
const REQUESTS_PER_MINUTE = 900;

app.disable('x-powered-by');

/* ---------- tiny in-memory rate limiter ---------- */
const hits = new Map();
setInterval(() => hits.clear(), 60 * 1000).unref();
app.use((req, res, next) => {
  const ip = req.ip;
  const n = (hits.get(ip) || 0) + 1;
  hits.set(ip, n);
  if (n > REQUESTS_PER_MINUTE) return res.status(429).send('Slow down a little and try again in a minute.');
  next();
});

/* ---------- safety: never let the proxy reach private/internal networks ---------- */
function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    p[0] === 0 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    p[0] >= 224
  );
}
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  const l = ip.toLowerCase();
  if (l === '::1' || l === '::') return true;
  if (l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb')) return true;
  const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}
async function assertPublic(u) {
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https addresses are supported.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error('That address is not reachable through the proxy.');
    return;
  }
  const addrs = await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('That address is not reachable through the proxy.');
  }
}

/* ---------- helpers ---------- */
const proxify = (abs) => '/proxy?url=' + encodeURIComponent(abs);

function normalizeInput(input) {
  input = (input || '').trim();
  if (!input) return null;
  if (/^https?:\/\//i.test(input)) return input;
  if (!/\s/.test(input) && /^[^\s/]+\.[a-z]{2,}([/:?#].*)?$/i.test(input)) return 'https://' + input;
  return 'https://duckduckgo.com/html/?q=' + encodeURIComponent(input);
}

function rewriteUrl(val, base) {
  if (!val) return val;
  const v = val.trim();
  if (!v || /^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(v)) return val;
  try {
    return proxify(new URL(v, base).href);
  } catch {
    return val;
  }
}

function rewriteSrcset(val, base) {
  return val
    .split(',')
    .map((part) => {
      const bits = part.trim().split(/\s+/);
      if (!bits[0]) return part;
      bits[0] = rewriteUrl(bits[0], base);
      return bits.join(' ');
    })
    .join(', ');
}

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => `url(${q}${rewriteUrl(u, base)}${q})`)
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => `@import ${q}${rewriteUrl(u, base)}${q}`);
}

function clientScript(baseUrl) {
  return `(function(){
var BASE=${JSON.stringify(baseUrl)};
function px(u){
  u=String(u);
  if(/^(data:|blob:|javascript:|about:|mailto:|tel:|#)/i.test(u)) return u;
  if(u.indexOf('/proxy?url=')===0) return u;
  try{ return '/proxy?url='+encodeURIComponent(new URL(u,BASE).href);}catch(e){return u;}
}
var of=window.fetch;
if(of){window.fetch=function(i,o){
  try{
    if(typeof i==='string') i=px(i);
    else if(i instanceof URL) i=px(i.href);
    else if(i&&i.url) i=new Request(px(i.url),i);
  }catch(e){}
  return of.call(this,i,o);
};}
var oo=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){ arguments[1]=px(u); return oo.apply(this,arguments); };
var ow=window.open;
window.open=function(u){ if(u) arguments[0]=px(u); return ow.apply(this,arguments); };
document.addEventListener('DOMContentLoaded',function(){
  var b=document.createElement('a');
  b.href='/'; b.textContent='⌂ Proxy home';
  b.style.cssText='position:fixed;right:12px;bottom:12px;z-index:2147483647;background:#111;color:#fff;font:13px system-ui,sans-serif;padding:8px 12px;border-radius:999px;text-decoration:none;opacity:.8;box-shadow:0 2px 10px rgba(0,0,0,.3)';
  document.body&&document.body.appendChild(b);
});
})();`;
}

function rewriteHtml(html, base) {
  const $ = cheerio.load(html);

  $('meta[http-equiv]').each((_, el) => {
    const he = ($(el).attr('http-equiv') || '').toLowerCase();
    if (he === 'content-security-policy') return $(el).remove();
    if (he === 'refresh') {
      const c = $(el).attr('content') || '';
      const m = c.match(/^(\s*\d+\s*;\s*url=)(.+)$/i);
      if (m) $(el).attr('content', m[1] + rewriteUrl(m[2].replace(/^['"]|['"]$/g, ''), base));
    }
  });
  $('base').remove();

  const attrs = ['href', 'src', 'poster', 'data-src', 'data-href', 'background'];
  $('*').each((_, el) => {
    const $el = $(el);
    for (const a of attrs) {
      const v = $el.attr(a);
      if (v) $el.attr(a, rewriteUrl(v, base));
    }
    const ss = $el.attr('srcset');
    if (ss) $el.attr('srcset', rewriteSrcset(ss, base));
    const ds = $el.attr('data-srcset');
    if (ds) $el.attr('data-srcset', rewriteSrcset(ds, base));
    const st = $el.attr('style');
    if (st) $el.attr('style', rewriteCss(st, base));
    $el.removeAttr('integrity');
    $el.removeAttr('nonce');
    $el.removeAttr('crossorigin');
  });

  $('style').each((_, el) => {
    $(el).text(rewriteCss($(el).text(), base));
  });

  $('form').each((_, el) => {
    const $f = $(el);
    const action = new URL($f.attr('action') || '', base).href;
    const method = ($f.attr('method') || 'get').toLowerCase();
    if (method === 'get') {
      $f.attr('action', '/proxy-form');
      $f.prepend(`<input type="hidden" name="__proxy_target" value="${action.replace(/"/g, '&quot;')}">`);
    } else {
      $f.attr('action', proxify(action));
    }
  });

  const script = `<script>${clientScript(base)}</script>`;
  if ($('head').length) $('head').prepend(script);
  else $.root().prepend(script);

  return $.html();
}

function errorPage(msg) {
  const safe = String(msg).replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
  return `<!doctype html><meta charset="utf-8"><title>Proxy error</title>
<body style="font-family:system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:0 20px;color:#222">
<h2>Couldn't load that page</h2><p>${safe}</p><p><a href="/">← Back to search</a></p></body>`;
}

/* ---------- core fetch with manual, validated redirects ---------- */
async function fetchUpstream(target, req) {
  let current = new URL(target);
  let method = req.method;
  let body = req.method === 'GET' || req.method === 'HEAD' ? undefined : req.body;

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    await assertPublic(current);
    const headers = {
      'user-agent': req.get('user-agent') || 'Mozilla/5.0',
      accept: req.get('accept') || '*/*',
      'accept-language': req.get('accept-language') || 'en-US,en;q=0.9',
    };
    if (body && req.get('content-type')) headers['content-type'] = req.get('content-type');

    const resp = await fetch(current, {
      method,
      headers,
      body: body && body.length ? body : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
    });

    if ([301, 302, 303, 307, 308].includes(resp.status) && resp.headers.get('location')) {
      current = new URL(resp.headers.get('location'), current);
      if (resp.status === 303 || ((resp.status === 301 || resp.status === 302) && method === 'POST')) {
        method = 'GET';
        body = undefined;
      }
      continue;
    }
    return { resp, finalUrl: current.href };
  }
  throw new Error('Too many redirects.');
}

async function handleProxy(req, res, target) {
  try {
    const { resp, finalUrl } = await fetchUpstream(target, req);

    const declared = Number(resp.headers.get('content-length') || 0);
    if (declared > MAX_BYTES) throw new Error('That file is too large for the proxy.');

    const ctype = resp.headers.get('content-type') || 'application/octet-stream';
    const buf = Buffer.from(await resp.arrayBuffer());
    if (buf.length > MAX_BYTES) throw new Error('That file is too large for the proxy.');

    res.status(resp.status);
    res.set('content-type', ctype);
    const cc = resp.headers.get('cache-control');
    if (cc) res.set('cache-control', cc);
    const cd = resp.headers.get('content-disposition');
    if (cd) res.set('content-disposition', cd);
    res.set('referrer-policy', 'no-referrer');

    if (/text\/html|application\/xhtml/i.test(ctype)) {
      return res.send(rewriteHtml(buf.toString('utf8'), finalUrl));
    }
    if (/text\/css/i.test(ctype)) {
      return res.send(rewriteCss(buf.toString('utf8'), finalUrl));
    }
    return res.send(buf);
  } catch (err) {
    const msg = err.name === 'TimeoutError' ? 'The site took too long to respond.' : err.message;
    res.status(502).type('html').send(errorPage(msg));
  }
}

/* ---------- routes ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.raw({ type: '*/*', limit: '10mb' }));

app.get('/go', (req, res) => {
  const t = normalizeInput(req.query.q);
  if (!t) return res.redirect('/');
  res.redirect(proxify(t));
});

app.all('/proxy', (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).type('html').send(errorPage('No address given.'));
  let u;
  try {
    u = new URL(target);
  } catch {
    return res.status(400).type('html').send(errorPage('That does not look like a valid address.'));
  }
  handleProxy(req, res, u.href);
});

app.get('/proxy-form', (req, res) => {
  const { __proxy_target, ...rest } = req.query;
  try {
    const u = new URL(__proxy_target);
    for (const [k, v] of Object.entries(rest)) u.searchParams.set(k, v);
    res.redirect(proxify(u.href));
  } catch {
    res.status(400).type('html').send(errorPage('Bad form target.'));
  }
});

app.listen(PORT, () => console.log(`Proxy running on http://localhost:${PORT}`));
