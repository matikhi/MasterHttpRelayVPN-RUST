/**
 * DomainFront Relay — Google Apps Script
 *
 * TWO modes:
 *  1. Single: POST { k, m, u, h, b, ct, r } → { s, h, b }
 *  2. Batch: POST { k, q: [{m,u,h,b,ct,r}, ...] } → { q: [{s,h,b}, ...] }
 *  Uses UrlFetchApp.fetchAll() — all URLs fetched IN PARALLEL.
 *
 * DEPLOYMENT:
 *  1. Go to script.google.com → New project
 *  2. Delete the default code, paste THIS entire file
 *  3. Open Project Settings (⚙️ icon) > Script Properties
 *  4. Add key-value pair: AUTH_KEY = <your_key_value>
 *  5. Click Deploy → New deployment
 *  6. Type: Web app | Execute as: Me | Who has access: Anyone
 *  7. Copy the Deployment ID into config.toml (previous config.json) as "script_id"
 *
 */
const PROPERTIES = PropertiesService.getScriptProperties();

const AUTH_KEY = PROPERTIES.getProperty("AUTH_KEY");

// Active-probing defense. When false (production default), bad AUTH_KEY
// requests get a decoy HTML page that looks like a placeholder Apps
// Script web app instead of the JSON `{"e":"unauthorized"}` body. This
// makes the deployment indistinguishable from a forgotten-but-public
// Apps Script project to active scanners that POST malformed payloads
// looking for proxy endpoints.
//
// Set to `true` during initial setup if a misconfigured client is
// hitting "unauthorized" and you want the explicit JSON error to debug
// — then flip back to false before the deployment is widely shared.
// (Inspired by #365 Section 3, mhrv-rs v1.8.0+.)
const DIAGNOSTIC_MODE = false;

// Connection-level + IP-leak request headers we strip before forwarding
// to the destination. Browser capability headers (sec-ch-ua*, sec-fetch-*)
// stay intact — modern apps like Google Meet use them for browser gating.
// We also drop the `X-Forwarded-*` / `Forwarded` / `Via` family so a
// misconfigured upstream proxy on the user side can't leak the user's
// real IP through the relay path. Mirrors upstream
// `masterking32/MasterHttpRelayVPN@3094288`.
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  "priority": 1, te: 1,
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "x-real-ip": 1, "forwarded": 1, "via": 1,
};

// Methods we consider safe to replay if `UrlFetchApp.fetchAll()` raises.
// GET/HEAD/OPTIONS are idempotent per RFC 9110; POST/PUT/PATCH/DELETE
// can have side-effects so we surface the error instead of silently
// re-firing them.
const SAFE_REPLAY_METHODS = { GET: 1, HEAD: 1, OPTIONS: 1 };

// HTML body for the bad-auth decoy. Mimics a minimal Apps Script-style
// placeholder page — no proxy-shaped JSON, nothing distinctive enough
// for a probe to fingerprint as a tunnel endpoint.
const DECOY_HTML =
  '<!DOCTYPE html><html><head><title>Web App</title></head>' +
  '<body><p>The script completed but did not return anything.</p>' +
  '</body></html>';

// ── Request Handlers ────────────────────────────────────────

function _decoyOrError (jsonBody) {
  if (DIAGNOSTIC_MODE) return _json(jsonBody);
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.XML);
}

function doPost (e) {
  try {
    let req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _decoyOrError({ e: "unauthorized" });

    // Batch mode: { k, q: [...] }
    if (Array.isArray(req.q)) return _doBatch(req.q);

    // Single mode
    return _doSingle(req);
  } catch (err) {
    // Parse failures of the request body are also probe-shaped — a real
    // mhrv-rs client never sends invalid JSON. Decoy for the same reason.
    return _decoyOrError({ e: String(err) });
  }
}

// `doGet` is what active scanners hit first (HTTP GET probes are cheaper
// than POSTs). Apps Script defaults to a "Script function not found" page
// here which is a fine-enough decoy on its own, but explicitly returning
// the same harmless placeholder makes the response identical to the
// bad-auth POST decoy — one less fingerprint vector.
function doGet (e) {
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.XML);
}

// ── Single Request ─────────────────────────────────────────

function _doSingle (req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  // ── Normal relay ────────
  // Wrap the fetch + body encode in try/catch so any failure surfaces as
  // a JSON error envelope the Rust client can parse. Without this, throws
  // from UrlFetchApp.fetch (URL too long, payload too large, quota
  // exhausted, 6-minute execution timeout) or from base64Encode (response
  // body near Apps Script's ~50 MB ceiling can blow the V8 heap during
  // encode) propagate unhandled, and Apps Script serves its default
  // `<title>Web App</title>` HTML error page — which the client then
  // reports as "Relay failed: bad response: no json in: <title>Web App>..."
  // and the user has no signal as to the actual cause. Mirrors the
  // per-item try/catch in _doBatch below.
  try {
    let opts = _buildOpts(req);
    let resp = UrlFetchApp.fetch(req.u, opts);

    // Raw-return mode for exit-node path.
    // r:true = return destination body verbatim so Rust gets {s,h,b} unwrapped.
    if (req.r === true) {
      try {
        let respContent = resp.getContentText();
        /** @type {Object} */
        let respObj = JSON.parse(respContent);
        if ([ "s", "h", "b" ].every(prop => respObj.hasOwnProperty(prop)))
          return ContentService
            .createTextOutput(respContent)
            .setMimeType(ContentService.MimeType.JSON);
      } catch {
        // exit-node format not matched, continuing normal relay
      }
    }


    return _json({
      s: resp.getResponseCode(),
      h: _respHeaders(resp),
      b: Utilities.base64Encode(resp.getContent()),
    });
  } catch (err) {
    return _json({ e: "fetch failed: " + String(err) });
  }
}

// ── Batch Request ──────────────────────────────────────────

function _doBatch (items) {
  let fetchArgs = [];
  let fetchIndex = [];
  let fetchMethods = [];
  let errorMap = {};

  for (let i = 0; i < items.length; i++) {
    let item = items[ i ];
    if (!item || typeof item !== "object") {
      errorMap[ i ] = "bad item";
      continue;
    }
    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[ i ] = "bad url";
      continue;
    }
    try {
      let opts = _buildOpts(item);
      opts.url = item.u;
      fetchArgs.push(opts);
      fetchIndex.push(i);
      fetchMethods.push(String(item.m || "GET").toUpperCase());
    } catch (buildErr) {
      errorMap[ i ] = String(buildErr);
    }
  }

  // fetchAll() processes all requests in parallel inside Google. If it
  // throws as a whole (e.g. one URL violates UrlFetchApp limits and
  // poisons the whole batch), degrade to per-item fetch on safe methods
  // so a single bad request does not zero out every response in the
  // batch. Mirrors upstream `masterking32/MasterHttpRelayVPN@3094288`.
  let responses = [];
  if (fetchArgs.length > 0) {
    try {
      responses = UrlFetchApp.fetchAll(fetchArgs);
    } catch (fetchAllErr) {
      responses = [];
      for (let j = 0; j < fetchArgs.length; j++) {
        try {
          if (!SAFE_REPLAY_METHODS[ fetchMethods[ j ] ]) {
            errorMap[ fetchIndex[ j ] ] =
              "batch fetchAll failed; unsafe method not replayed";
            responses[ j ] = null;
            continue;
          }
          let fallbackReq = fetchArgs[ j ];
          let fallbackUrl = fallbackReq.url;
          let fallbackOpts = {};
          for (let key in fallbackReq) {
            if (
              Object.prototype.hasOwnProperty.call(fallbackReq, key) &&
              key !== "url"
            ) {
              fallbackOpts[ key ] = fallbackReq[ key ];
            }
          }
          responses[ j ] = UrlFetchApp.fetch(fallbackUrl, fallbackOpts);
        } catch (singleErr) {
          errorMap[ fetchIndex[ j ] ] = String(singleErr);
          responses[ j ] = null;
        }
      }
    }
  }

  let results = [];
  let rIdx = 0;
  for (let i = 0; i < items.length; i++) {
    if (Object.prototype.hasOwnProperty.call(errorMap, i)) {
      results.push({ e: errorMap[ i ] });
    } else {
      let resp = responses[ rIdx++ ];
      if (!resp) {
        results.push({ e: "fetch failed" });
      } else {
        results.push({
          s: resp.getResponseCode(),
          h: _respHeaders(resp),
          b: Utilities.base64Encode(resp.getContent()),
        });
      }
    }
  }
  return _json({ q: results });
}

// ── Request Building ───────────────────────────────────────

function _buildOpts (req) {
  let opts = {
    method: (req.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: true,          // ← always true; r flag now has different meaning
    validateHttpsCertificates: true,
    escaping: false,
  };
  if (req.h && typeof req.h === "object") {
    let headers = {};
    for (let k in req.h) {
      if (req.h.hasOwnProperty(k) && !SKIP_HEADERS[ k.toLowerCase() ]) {
        headers[ k ] = req.h[ k ];
      }
    }
    opts.headers = headers;
  }
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

function _respHeaders (resp) {
  try {
    if (typeof resp.getAllHeaders === "function") {
      return resp.getAllHeaders();
    }
  } catch (err) { }
  return resp.getHeaders();
}

function _json (obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}
