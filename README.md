# Lantern: a simple self-hosted web proxy

A small Node.js web proxy. You type a URL or a search, and the server fetches the page for you and rewrites its links, images, CSS and forms so everything keeps loading through the proxy.

## Run it

```bash
npm install
npm start
# open http://localhost:3000
```

Requires Node 18 or newer.

## Deploy it

Any host that runs Node works (Render, Railway, Fly.io, a VPS). Set the start command to `npm start`. The `PORT` environment variable is respected.

## What it does

- Fetches pages server-side and rewrites links, images, scripts, stylesheets (`url()` and `@import`), `srcset`, and meta refreshes.
- Intercepts `fetch`, `XMLHttpRequest` and `window.open` in the page so dynamic requests also go through the proxy.
- Handles GET and POST forms, and follows redirects (re-validating every hop).
- Turns plain text in the box into a DuckDuckGo search.
- Strips CSP meta tags and blocks requests to private/internal IP ranges (so it can't be used to poke at your own network).
- Basic per-IP rate limiting.

## Honest limitations

- **It can't override restrictions on a device.** A proxy only helps if the device can reach the proxy's own address. Managed devices (school or work Chromebooks, MDM, DNS filtering, or filters that block new proxy domains) can block the proxy itself, and nothing in a website can change that.
- **Cookies and logins aren't forwarded**, so sites that need you to sign in generally won't work.
- **No WebSocket support**, and heavy apps and video streaming sites (YouTube, Netflix, Google apps) won't work well.
- **Sites that actively detect proxies or block datacenter IPs** may refuse to load.
- JavaScript-heavy single-page apps that build URLs in unusual ways can still escape the rewriting.
- DNS is checked before each request, but this is not a hardened defense against DNS rebinding. Don't expose it publicly without adding more protection.

## Please be considerate

Running a proxy publicly means other people's traffic comes from your server. Add authentication and stricter rate limits before sharing it widely, and follow the rules of whatever network or device you're on.
