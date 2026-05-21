/**
 * RemoraHQ - Integrations MeshCentral plugin.
 *
 * Server-side proxy for Jira REST. Reads JIRA_API_KEY (and optionally
 * JIRA_EMAIL) from process.env; falls back to a `.env` file in the plugin
 * directory if process.env is empty. The token never leaves the server.
 *
 * Wire envelope follows the RemoraHQ plugin convention (see remoraCore.js
 * comment header). Two pluginactions:
 *   - jira.test    GET /rest/api/3/myself      verifies key + baseUrl
 *   - jira.create  POST /rest/api/3/issue      creates an issue
 *
 * Auth:
 *   - JIRA_EMAIL set → Basic base64(email:token)        (Jira Cloud)
 *   - JIRA_EMAIL empty → Bearer token                   (Jira Server PAT)
 *
 * Errors are returned to the client as `{ result:'error', error:'<short>' }`
 * — the RemoraHQ UI surfaces them in a toast.
 */

'use strict';

var fs = require('fs');
var path = require('path');
var https = require('https');
var http = require('http');
var url = require('url');

var PLUGIN_SHORT_NAME = 'remoraIntegrations';
var PLUGIN_VERSION = '0.1.0';
var JIRA_TIMEOUT_MS = 15000;

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

function jiraErrorMessage(status, body) {
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
                runJiraTest(command).then(function (data) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'ok', userEmail: data.userEmail, displayName: data.displayName });
                }).catch(function (err) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err && err.message ? err.message : err) });
                });
                return;
            }
            case 'jira.create': {
                runJiraCreate(command).then(function (data) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'ok', key: data.key, url: data.url });
                }).catch(function (err) {
                    sendReply(session, pluginAction, tag, responseid, { result: 'error', error: String(err && err.message ? err.message : err) });
                });
                return;
            }
            default: {
                sendReply(session, pluginAction || 'unknown', tag, responseid, { result: 'error', error: 'unknown_pluginaction' });
                return;
            }
        }
    };

    function runJiraTest(command) {
        return new Promise(function (resolve, reject) {
            var auth = buildAuthHeader();
            if (!auth) return reject(new Error('jira_api_key_missing'));
            var baseUrl = command.baseUrl;
            if (!baseUrl || typeof baseUrl !== 'string') return reject(new Error('invalid_baseUrl'));
            httpRequest('GET', joinUrl(baseUrl, '/rest/api/3/myself'), {
                'Authorization': auth,
                'Accept': 'application/json'
            }, undefined).then(function (res) {
                if (res.status >= 200 && res.status < 300) {
                    var body = res.body || {};
                    return resolve({ userEmail: body.emailAddress || '', displayName: body.displayName || '' });
                }
                return reject(new Error(jiraErrorMessage(res.status, res.body)));
            }).catch(reject);
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

            var payload = {
                fields: {
                    project: { key: projectKey },
                    issuetype: { name: issueType },
                    summary: summary,
                    description: adfDescription(description)
                }
            };

            httpRequest('POST', joinUrl(baseUrl, '/rest/api/3/issue'), {
                'Authorization': auth,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }, payload).then(function (res) {
                if (res.status >= 200 && res.status < 300) {
                    var body = res.body || {};
                    var key = body.key || '';
                    var browseUrl = key ? (String(baseUrl).replace(/\/+$/, '') + '/browse/' + encodeURIComponent(key)) : '';
                    return resolve({ key: key, url: browseUrl });
                }
                return reject(new Error(jiraErrorMessage(res.status, res.body)));
            }).catch(reject);
        });
    }

    return obj;
};
