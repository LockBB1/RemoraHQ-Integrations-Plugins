# RemoraHQ - Integrations

MeshCentral plugin that proxies RemoraHQ Send-to-Admin requests to external trackers. Currently ships a Jira REST connector. PSO and SIEM connectors live elsewhere (PSO is browser-only via copy/paste; SIEM is planned).

## Configuration

The Jira API token is **server-side only** — it never touches the browser. The plugin reads it from environment variables on Mesh server start.

1. Copy `.env.example` to `.env` in the plugin directory.
2. Fill in `JIRA_API_KEY` (and `JIRA_EMAIL` for Jira Cloud).
3. Restart MeshCentral.

`baseUrl`, `projectKey`, `issueType` are configured per-admin in the RemoraHQ UI (`Admin → Integrations → Jira`). The plugin will refuse `jira.create` calls if `JIRA_API_KEY` is not set.

## Auth modes

- **Jira Cloud:** Basic auth using `JIRA_EMAIL:JIRA_API_KEY`.
- **Jira Server / Data Center:** Bearer auth using `JIRA_API_KEY` (Personal Access Token).

The plugin picks Basic if `JIRA_EMAIL` is set, otherwise Bearer.

### Optional `JIRA_LOGIN` (default assignee)

On some Jira Server / DC projects the create screen requires `assignee`. Jira then returns a misleading `Could not find issuetype` error instead of the real "assignee required" message. Set `JIRA_LOGIN` to the username of any valid Jira account (e.g. a service account) and the plugin will populate `fields.assignee = { name: JIRA_LOGIN }` on every created issue.

## Wire protocol

Standard RemoraHQ plugin envelope. Two pluginactions:

### `jira.test`

```js
client → { action:'plugin', plugin:'remoraIntegrations', pluginaction:'jira.test',
           tag, responseid, baseUrl }
server → { result:'ok', userEmail, displayName }   // GET /rest/api/{3,2}/myself
       | { result:'error', error }
```

### `jira.create`

```js
client → { action:'plugin', plugin:'remoraIntegrations', pluginaction:'jira.create',
           tag, responseid, baseUrl, projectKey, issueType?, summary, description }
server → { result:'ok', key, url }   // POST /rest/api/{3,2}/issue
       | { result:'error', error }
```

Both actions probe v3 (Cloud) first, then fall back to v2 (Server/DC) on
404 OR any 3xx redirect — Jira Server/DC 9.x responds to unknown REST
paths like `/rest/api/3/myself` with a 302 → `/login.jsp` even when the
Bearer PAT successfully authenticates (Seraph still returns
`x-seraph-loginreason: OK`), so a 404-only fallback would never reach v2.

## Limits

- No retries (the operator will see a toast and can re-submit).
- No queue (one ticket per click).
- 15-second connect timeout.

## License

Apache-2.0.
