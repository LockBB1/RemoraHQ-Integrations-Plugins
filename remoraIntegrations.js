/**
 * RemoraHQ - Integrations MeshCentral plugin.
 *
 * Server-side proxy for Jira REST. Reads JIRA_API_KEY (and optionally
 * JIRA_EMAIL) from process.env; falls back to a `.env` file in the plugin
 * directory if process.env is empty. The token never leaves the server.
 *
 * Wire envelope follows the RemoraHQ plugin convention (see remoraCore.js
 * comment header). Two pluginactions:
 *   - jira.test    GET /rest/api/{3,2}/myself  verifies key + baseUrl
 *   - jira.create  POST /rest/api/{3,2}/issue  creates an issue
 *
 * Endpoint probe order is v3 (Cloud) → v2 (Server/DC). Jira Server/DC 9.x
 * responds to unknown REST paths (like /rest/api/3/*) with a 302 redirect
 * to /login.jsp — NOT a 404 — even with a valid Bearer PAT. The fallback
 * therefore triggers on 404 OR any 3xx, otherwise the v2 path is never
 * tried on Server/DC.
 *
 * Auth:
 *   - JIRA_EMAIL set → Basic base64(email:token)        (Jira Cloud)
 *   - JIRA_EMAIL empty → Bearer token                   (Jira Server PAT)
 *
 * Errors are returned to the client as `{ result:'error', error:'<short>' }`
 * — the RemoraHQ UI surfaces them in a toast.
 *
 * v0.3.0 (AUDIT-5 #34) — SSRF / credential-exfil hardening:
 *   - jira.create sources baseUrl/projectKey/issueType/assignee from the
 *     server-stored config doc, NEVER the client, so the credentialed request
 *     cannot be redirected. The client supplies only summary/description/
 *     reporter. This restores the "token never leaves the server" invariant.
 *   - jira.test is now admin-only (isAdminSession), matching the config writes.
 *   - Both reject non-HTTPS and private/loopback/link-local hosts before the
 *     credential is sent (assertSafeJiraUrl).
 */

'use strict';

var fs = require('fs');
var path = require('path');
var https = require('https');
var http = require('http');
var url = require('url');

var PLUGIN_SHORT_NAME = 'remoraIntegrations';
var PLUGIN_VERSION = '0.3.0';
var JIRA_TIMEOUT_MS = 15000;

// v0.2.0 (RC-13.18 / B-13.5/2). Singleton Mesh DB doc holding the
// non-secret integration config (baseUrl, projectKey, issueType,
// assignee for Jira; baseUrl for PSO). Prior to v0.2.0 these lived in
// each user's localStorage, so an Operator never saw the config the
// Admin had entered. The Jira API token still lives in process.env on
// the server — that secret never travels through this channel.
var CONFIG_DOC_ID = 'remoraIntegrationsConfig';

function emptyConfig() {
    return { jira: null, pso: null, configuredAt: null };
}

function readConfig(meshServer, callback) {
    if (!meshServer || !meshServer.db || typeof meshServer.db.Get !== 'function') {
        callback(emptyConfig());
        return;
    }
    meshServer.db.Get(CONFIG_DOC_ID, function (err, docs) {
        if (err || !docs || docs.length === 0) { callback(emptyConfig()); return; }
        var doc = docs[0] || {};
        callback({
            jira: (doc.jira && typeof doc.jira === 'object') ? doc.jira : null,
            pso: (doc.pso && typeof doc.pso === 'object') ? doc.pso : null,
            configuredAt: typeof doc.configuredAt === 'string' ? doc.configuredAt : null
        });
    });
}

function writeConfig(meshServer, next, callback) {
    if (!meshServer || !meshServer.db || typeof meshServer.db.Set !== 'function') {
        callback(new Error('no_db'));
        return;
    }
    var doc = {
        _id: CONFIG_DOC_ID,
        type: 'remoraIntegrationsConfig',
        jira: next.jira || null,
        pso: next.pso || null,
        configuredAt: new Date().toISOString()
    };
    meshServer.db.Set(doc, function (err) { callback(err || null, doc); });
}

/**
 * Admin gate for write operations. We require Mesh's full siteadmin
 * (0xFFFFFFFF) — same bit Mesh's own native config UI checks. Operators
 * can READ the config (so they can submit bug reports) but cannot edit.
 */
function isAdminSession(sessionObj) {
    var u = sessionObj && sessionObj.user;
    if (!u) return false;
    return u.siteadmin === 0xFFFFFFFF;
}

function sanitizeJiraConfig(raw) {
    if (!raw || typeof raw !== 'object') return null;
    var baseUrl = typeof raw.baseUrl === 'string' ? raw.baseUrl.trim() : '';
    var projectKey = typeof raw.projectKey === 'string' ? raw.projectKey.trim() : '';
    if (!baseUrl || !projectKey) return null;
    var out = { baseUrl: baseUrl, projectKey: projectKey };
    if (typeof raw.issueType === 'string' && raw.issueType.trim()) out.issueType = raw.issueType.trim();
    if (typeof raw.assignee === 'string' && raw.assignee.trim()) out.assignee = raw.assignee.trim();
    return out;
}

function sanitizePsoConfig(raw) {
    if (!raw || typeof raw !== 'object') return null;
    var baseUrl = typeof raw.baseUrl === 'string' ? raw.baseUrl.trim() : '';
    if (!baseUrl) return null;
    return { baseUrl: baseUrl };
}

// v0.3.0 (AUDIT-5 #34). SSRF / credential-exfil hardening. Reject any request
// target that is not plain HTTPS to a non-private host, so the credentialed
// Jira request cannot be redirected at an attacker host or the cloud-metadata
// endpoint. Residual accepted pre-beta: a public hostname that DNS-resolves to
// a private IP (rebinding) — the primary exfil path is already closed by
// sourcing `baseUrl` from the server-stored config in jira.create, never the
// client.
function isPrivateHostname(h) {
    if (!h) return true;
    var host = String(h).toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
    if (host === 'localhost' || /\.localhost$/.test(host)) return true;
    if (host === '::1') return true;                                   // IPv6 loopback
    if (host.indexOf('fe80:') === 0) return true;                      // IPv6 link-local
    if (host.indexOf('fc') === 0 || host.indexOf('fd') === 0) return true; // IPv6 unique-local
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (m) {
        var a = +m[1], b = +m[2];
        if (a === 0 || a === 10 || a === 127) return true;             // this-net / private / loopback
        if (a === 169 && b === 254) return true;                       // link-local + cloud metadata
        if (a === 172 && b >= 16 && b <= 31) return true;              // private
        if (a === 192 && b === 168) return true;                       // private
        if (a === 100 && b >= 64 && b <= 127) return true;             // CGNAT
    }
    return false;
}

// Returns a short error slug if the URL is unsafe to send a credential to,
// else null.
function assertSafeJiraUrl(rawUrl) {
    var parsed;
    try { parsed = url.parse(String(rawUrl || '')); } catch (e) { return 'invalid_baseUrl'; }
    if (parsed.protocol !== 'https:') return 'baseUrl_must_be_https';
    if (isPrivateHostname(parsed.hostname)) return 'baseUrl_host_forbidden';
    return null;
}

/**
 * Minimal .env loader — no dependency on `dotenv`. Reads KEY=VALUE lines,
 * strips surrounding quotes, ignores comments and blanks. Only sets keys
 * that are NOT already in process.env (process.env wins over .env so
 * systemd / shell exports stay authoritative).
 */
function loadDotEnv(filePath) {
    var loaded = 0;
    try {
        if (!fs.existsSync(filePath)) return 0;
        var content = fs.readFileSync(filePath, 'utf8');
        var lines = content.split(/\r?\n/);
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line || line.indexOf('#') === 0) continue;
            var eq = line.indexOf('=');
            if (eq < 1) continue;
            var key = line.slice(0, eq).trim();
            var value = line.slice(eq + 1).trim();
            if ((value.length >= 2) && ((value[0] === '"' && value[value.length - 1] === '"') || (value[0] === "'" && value[value.length - 1] === "'"))) {
                value = value.slice(1, -1);
            }
            if (process.env[key] === undefined) {
                process.env[key] = value;
                loaded++;
            }
        }
    } catch (_e) {
        // Non-fatal — plugin will report missing key on first jira.create.
    }
    return loaded;
}

function buildAuthHeader() {
    var token = process.env.JIRA_API_KEY;
    if (!token) return null;
    var email = process.env.JIRA_EMAIL;
    if (email) {
        var basic = Buffer.from(email + ':' + token, 'utf8').toString('base64');
        return 'Basic ' + basic;
    }
    return 'Bearer ' + token;
}

/**
 * Promise wrapper around https.request. Returns { status, body, headers }.
 * Rejects on network/timeout errors. Body is parsed as JSON if Content-Type
 * looks like JSON, otherwise returned as a raw string.
 */
function httpRequest(method, fullUrl, headers, bodyJson) {
    return new Promise(function (resolve, reject) {
        var parsed;
        try { parsed = url.parse(fullUrl); } catch (e) { return reject(new Error('invalid_url')); }
        if (!parsed.protocol || (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')) {
            return reject(new Error('invalid_protocol'));
        }
        var transport = parsed.protocol === 'https:' ? https : http;
        var opts = {
            method: method,
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.path,
            headers: headers || {}
        };
        var req = transport.request(opts, function (res) {
            var chunks = [];
            res.on('data', function (c) { chunks.push(c); });
            res.on('end', function () {
                var raw = Buffer.concat(chunks).toString('utf8');
                var parsedBody = raw;
                var ct = String(res.headers['content-type'] || '');
                if (ct.indexOf('application/json') !== -1 && raw.length > 0) {
                    try { parsedBody = JSON.parse(raw); } catch (_e) { /* keep raw */ }
                }
                resolve({ status: res.statusCode || 0, body: parsedBody, headers: res.headers });
            });
        });
        req.on('error', reject);
        req.setTimeout(JIRA_TIMEOUT_MS, function () {
            req.destroy(new Error('timeout'));
        });
        if (bodyJson !== undefined) req.write(JSON.stringify(bodyJson));
        req.end();
    });
}

function joinUrl(baseUrl, suffix) {
    if (!baseUrl) return suffix;
    return String(baseUrl).replace(/\/+$/, '') + suffix;
}

function adfDescription(text) {
    var safe = typeof text === 'string' ? text : '';
    // Split on blank lines so multi-paragraph descriptions render correctly
    // in Jira Cloud's ADF renderer. Each paragraph keeps its line breaks via
    // hardBreak nodes.
    var blocks = safe.split(/\n\s*\n/);
    var content = [];
    for (var i = 0; i < blocks.length; i++) {
        var block = blocks[i];
        var lines = block.split('\n');
        var paragraphContent = [];
        for (var j = 0; j < lines.length; j++) {
            if (j > 0) paragraphContent.push({ type: 'hardBreak' });
            if (lines[j].length > 0) paragraphContent.push({ type: 'text', text: lines[j] });
        }
        content.push({ type: 'paragraph', content: paragraphContent });
    }
    return { type: 'doc', version: 1, content: content };
}

function sendReply(session, pluginAction, tag, responseid, payload) {
    var msg = {
        action: 'plugin',
        plugin: PLUGIN_SHORT_NAME,
        pluginaction: pluginAction,
        tag: tag,
        responseid: responseid
    };
    for (var k in payload) {
        if (Object.prototype.hasOwnProperty.call(payload, k)) msg[k] = payload[k];
    }
    session.send(msg);
}

function jiraErrorMessage(status, body, headers) {
    // Redirects from Jira REST are almost always one of:
    //   - auth failed → Jira sends you to login page
    //   - baseUrl is wrong / missing context path (Server: /jira)
    //   - http vs https mismatch
    // Surface the Location header so the admin can see exactly where Jira
    // wanted us to go.
    if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) {
        var loc = headers && (headers.location || headers.Location);
        var locHint = loc ? ' → ' + String(loc).slice(0, 200) : '';
        if (loc && /login|signin|sso/i.test(String(loc))) {
            return 'jira_http_' + status + '_auth_redirect' + locHint + ' (check JIRA_API_KEY / JIRA_EMAIL)';
        }
        return 'jira_http_' + status + locHint + ' (check baseUrl — Jira Server often needs the context path, e.g. https://host/jira)';
    }
    if (status === 401) return 'jira_http_401_unauthorized (check JIRA_API_KEY / JIRA_EMAIL)';
    if (status === 403) return 'jira_http_403_forbidden (token lacks permission to create/read issues)';
    if (status === 404) return 'jira_http_404 (REST endpoint not found at this baseUrl)';
    if (body && typeof body === 'object') {
        if (Array.isArray(body.errorMessages) && body.errorMessages.length > 0) {
            return String(body.errorMessages[0]);
        }
        if (body.errors && typeof body.errors === 'object') {
            var keys = Object.keys(body.errors);
            if (keys.length > 0) return keys[0] + ': ' + String(body.errors[keys[0]]);
        }
        if (typeof body.message === 'string') return body.message;
    }
    return 'jira_http_' + status;
}

module.exports.remoraIntegrations = function (parent) {
    var obj = {};
    obj.parent = parent;
    obj.meshServer = parent.parent;

    obj.exports = ['serveraction'];

    obj.server_startup = function () {
        var envPath = path.join(__dirname, '.env');
        var loaded = loadDotEnv(envPath);
        var hasKey = Boolean(process.env.JIRA_API_KEY);
        console.log('[remoraIntegrations] v' + PLUGIN_VERSION + ' loaded. JIRA_API_KEY ' + (hasKey ? 'present' : 'MISSING') + ' (.env loaded ' + loaded + ' vars).');
        if (!hasKey) {
            console.warn('[remoraIntegrations] Set JIRA_API_KEY in ' + envPath + ' or via process.env before jira.* calls will succeed.');
        }
    };

    obj.serveraction = function (command, dbGet, ws) {
        var session = dbGet || ws;
        if (!session || typeof session.send !== 'function') return;

        var pluginAction = String(command.pluginaction || '');
        var tag = command.tag;
        var responseid = command.responseid || tag;

        switch (pluginAction) {
            case 'jira.test': {
                // v0.3.0 (AUDIT-5 #34). Admin-only connection test — this is the
                // config UI's "Test" button, where the admin enters the baseUrl
                // being validated. Gate it (same bar as config writes) so a
                // non-admin can no longer drive a credentialed request, and
                // reject non-HTTPS / private-host targets.
                if (!isAdminSession(dbGet)) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'forbidden' });
                    return;
                }
                var badTestUrl = assertSafeJiraUrl(command.baseUrl);
                if (badTestUrl) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: badTestUrl });
                    return;
                }
                runJiraTest(command).then(function (data) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'ok', userEmail: data.userEmail, displayName: data.displayName });
                }).catch(function (err) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err && err.message ? err.message : err) });
                });
                return;
            }
            case 'jira.create': {
                // v0.3.0 (AUDIT-5 #34). Operator-callable (bug reports), so it
                // is NOT admin-gated — but the request target MUST come from the
                // server-stored config, never the client `baseUrl`/`projectKey`.
                // Previously a caller could redirect the credentialed request at
                // an attacker host (JIRA token exfiltration) or an internal
                // address (SSRF). The client only supplies summary/description/
                // reporter; everything that selects the destination is read from
                // the admin-configured doc.
                readConfig(obj.meshServer, function (cfg) {
                    if (!cfg.jira || !cfg.jira.baseUrl || !cfg.jira.projectKey) {
                        sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'not_configured' });
                        return;
                    }
                    var badCreateUrl = assertSafeJiraUrl(cfg.jira.baseUrl);
                    if (badCreateUrl) {
                        sendReply(session, pluginAction, tag, responseid, { result: 'error', error: badCreateUrl });
                        return;
                    }
                    var safeCommand = {
                        baseUrl: cfg.jira.baseUrl,
                        projectKey: cfg.jira.projectKey,
                        issueType: cfg.jira.issueType || command.issueType,
                        assigneeName: cfg.jira.assignee || command.assigneeName,
                        reporterName: command.reporterName,
                        summary: command.summary,
                        description: command.description
                    };
                    runJiraCreate(safeCommand).then(function (data) {
                        sendReply(session, pluginAction, tag, responseid, { result: 'ok', key: data.key, url: data.url });
                    }).catch(function (err) {
                        sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err && err.message ? err.message : err) });
                    });
                });
                return;
            }
            case 'config.get': {
                // v0.2.0. Returns the deployment-wide integration config so
                // every authenticated user (Operator included) sees the same
                // "is integration configured" answer the admin entered. No
                // secrets travel here — Jira API token stays in process.env.
                readConfig(obj.meshServer, function (cfg) {
                    sendReply(session, pluginAction, tag, responseid, {
                        result: 'ok',
                        jira: cfg.jira,
                        pso: cfg.pso,
                        configuredAt: cfg.configuredAt
                    });
                });
                return;
            }
            case 'config.setJira': {
                // v0.2.0. Admin-only write. We re-read existing doc so PSO
                // config (if any) is preserved across Jira-only updates.
                if (!isAdminSession(dbGet)) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'forbidden' });
                    return;
                }
                var nextJira = sanitizeJiraConfig(command.jira);
                if (!nextJira) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'invalid_payload' });
                    return;
                }
                readConfig(obj.meshServer, function (cur) {
                    writeConfig(obj.meshServer, { jira: nextJira, pso: cur.pso }, function (err, doc) {
                        if (err) {
                            sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err.message || err) });
                            return;
                        }
                        sendReply(session, pluginAction, tag, responseid, {
                            result: 'ok',
                            jira: doc.jira,
                            pso: doc.pso,
                            configuredAt: doc.configuredAt
                        });
                    });
                });
                return;
            }
            case 'config.setPso': {
                if (!isAdminSession(dbGet)) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'forbidden' });
                    return;
                }
                var nextPso = sanitizePsoConfig(command.pso);
                if (!nextPso) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'invalid_payload' });
                    return;
                }
                readConfig(obj.meshServer, function (cur) {
                    writeConfig(obj.meshServer, { jira: cur.jira, pso: nextPso }, function (err, doc) {
                        if (err) {
                            sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err.message || err) });
                            return;
                        }
                        sendReply(session, pluginAction, tag, responseid, {
                            result: 'ok',
                            jira: doc.jira,
                            pso: doc.pso,
                            configuredAt: doc.configuredAt
                        });
                    });
                });
                return;
            }
            case 'config.remove': {
                if (!isAdminSession(dbGet)) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'forbidden' });
                    return;
                }
                var providerId = String(command.providerId || '');
                if (providerId !== 'jira' && providerId !== 'pso') {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: 'invalid_providerId' });
                    return;
                }
                readConfig(obj.meshServer, function (cur) {
                    var next = { jira: cur.jira, pso: cur.pso };
                    next[providerId] = null;
                    writeConfig(obj.meshServer, next, function (err, doc) {
                        if (err) {
                            sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err.message || err) });
                            return;
                        }
                        sendReply(session, pluginAction, tag, responseid, {
                            result: 'ok',
                            jira: doc.jira,
                            pso: doc.pso,
                            configuredAt: doc.configuredAt
                        });
                    });
                });
                return;
            }
            default: {
                sendReply(session, pluginAction || 'unknown', tag, responseid, { result: 'error', error: 'unknown_pluginaction' });
                return;
            }
        }
    };

    /**
     * Run a GET /myself probe and try v3 (Cloud) first, then v2 (Server/DC)
     * on 404 OR any 3xx redirect. Jira Server/DC 9.x answers unknown REST
     * paths like /rest/api/3/myself with a 302 → /login.jsp (even with a
     * valid Bearer PAT — Seraph still says x-seraph-loginreason: OK), so a
     * 404-only fallback misses the real v3-not-supported case.
     */
    function runJiraTest(command) {
        return new Promise(function (resolve, reject) {
            var auth = buildAuthHeader();
            if (!auth) return reject(new Error('jira_api_key_missing'));
            var baseUrl = command.baseUrl;
            if (!baseUrl || typeof baseUrl !== 'string') return reject(new Error('invalid_baseUrl'));

            var headers = { 'Authorization': auth, 'Accept': 'application/json' };

            function tryVersion(apiVersion, next) {
                httpRequest('GET', joinUrl(baseUrl, '/rest/api/' + apiVersion + '/myself'), headers, undefined)
                    .then(function (res) {
                        if (res.status >= 200 && res.status < 300) {
                            var body = res.body || {};
                            return resolve({
                                userEmail: body.emailAddress || '',
                                displayName: body.displayName || '',
                                apiVersion: apiVersion
                            });
                        }
                        if (next && (res.status === 404 || (res.status >= 300 && res.status < 400))) {
                            return next();
                        }
                        return reject(new Error(jiraErrorMessage(res.status, res.body, res.headers)));
                    })
                    .catch(reject);
            }

            // Cloud → Server
            tryVersion(3, function () { tryVersion(2, null); });
        });
    }

    function runJiraCreate(command) {
        return new Promise(function (resolve, reject) {
            var auth = buildAuthHeader();
            if (!auth) return reject(new Error('jira_api_key_missing'));
            var baseUrl = command.baseUrl;
            var projectKey = command.projectKey;
            var summary = command.summary;
            var description = command.description;
            var issueType = command.issueType || 'Bug';
            if (!baseUrl || typeof baseUrl !== 'string') return reject(new Error('invalid_baseUrl'));
            if (!projectKey || typeof projectKey !== 'string') return reject(new Error('invalid_projectKey'));
            if (!summary || typeof summary !== 'string') return reject(new Error('invalid_summary'));
            if (typeof description !== 'string') description = '';

            var headers = {
                'Authorization': auth,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            };

            // Jira accepts issuetype as either {id:"10004"} or {name:"Bug"}.
            // Names are locale-sensitive and break after admin rename; ids
            // are stable. Treat a digits-only value as an id.
            var issueTypeRef = /^\d+$/.test(String(issueType))
                ? { id: String(issueType) }
                : { name: String(issueType) };

            // Assignee precedence: client-provided assigneeName (from UI
            // config) > JIRA_LOGIN env (legacy fallback). If both empty,
            // assignee is omitted so Jira uses the project default.
            var assigneeName = command.assigneeName;
            if (!assigneeName) assigneeName = process.env.JIRA_LOGIN || '';

            // Reporter: when client passes reporterName, override the
            // PAT-account-as-author behaviour so the actual end user that
            // clicked "Create" is the reporter in Jira. Requires the PAT
            // account to have "Modify Reporter" permission in the project.
            var reporterName = command.reporterName;

            function payloadFor(apiVersion) {
                var fields = {
                    project: { key: projectKey },
                    issuetype: issueTypeRef,
                    summary: summary
                };
                if (assigneeName) {
                    fields.assignee = { name: String(assigneeName) };
                }
                if (reporterName) {
                    fields.reporter = { name: String(reporterName) };
                }
                // Jira Cloud (v3) wants ADF; Jira Server / DC (v2) wants a plain string.
                fields.description = (apiVersion === 3) ? adfDescription(description) : description;
                return { fields: fields };
            }

            function tryVersion(apiVersion, next) {
                httpRequest('POST', joinUrl(baseUrl, '/rest/api/' + apiVersion + '/issue/'), headers, payloadFor(apiVersion))
                    .then(function (res) {
                        if (res.status >= 200 && res.status < 300) {
                            var body = res.body || {};
                            var key = body.key || '';
                            var browseUrl = key ? (String(baseUrl).replace(/\/+$/, '') + '/browse/' + encodeURIComponent(key)) : '';
                            return resolve({ key: key, url: browseUrl, apiVersion: apiVersion });
                        }
                        if (next && (res.status === 404 || (res.status >= 300 && res.status < 400))) {
                            return next();
                        }
                        return reject(new Error(jiraErrorMessage(res.status, res.body, res.headers)));
                    })
                    .catch(reject);
            }

            tryVersion(3, function () { tryVersion(2, null); });
        });
    }

    return obj;
};
