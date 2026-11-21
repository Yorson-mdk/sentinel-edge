# Sentinel Edge

A small Cloudflare Workers starter that combines heuristic request monitoring with an application audit-event endpoint and a dashboard. It is intended as a learning and customization project, not a replacement for Cloudflare WAF or a production SIEM.

## What it does

- Inspects requests that reach the Worker for rate spikes, sensitive-path probes, common scanner user agents, unusual methods, and missing user agents.
- Logs matching requests to Workers KV. Blocking is off by default; when enabled, path probes and recognized scanners receive a 403.
- Serves a dashboard at `/_sentinel` with a recent detection list and a separate application audit view.
- Accepts structured website audit events at `POST /api/ingest`.
- Supports multiple alias hostnames routed to the same Worker and website origin.

The dashboard starts with clearly labeled sample data. Live records appear after deployment and connection. Application audit events appear only when the website backend sends them; the Worker does not infer user actions such as sign-ins or role changes.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the request-flow diagram and data scope.

## Local development

1. Install Node.js and npm.
2. Install dependencies with `npm install`.
3. Copy `.dev.vars.example` to `.dev.vars` and set local values.
4. Configure the KV namespace in `wrangler.jsonc`, or use Wrangler's local KV simulation.
5. Start the local Worker with `npm run dev`.

The site origin placeholder is `https://your-origin.example.com`. Replace it with the actual upstream origin when deploying. Do not set it to a hostname whose traffic routes back to this Worker, which can create a proxy loop.

## Cloudflare deployment

1. Sign in with `npx wrangler login`.
2. Create a KV namespace: `npx wrangler kv namespace create IDS_KV`.
3. Put the returned namespace ID in `wrangler.jsonc` in place of `REPLACE_WITH_KV_NAMESPACE_ID`.
4. Set the upstream website origin in the Worker configuration. If the origin contains private credentials, store it with `npx wrangler secret put ORIGIN_URL` rather than in `vars`.
5. Set two separate secrets:

   ```sh
   npx wrangler secret put DASHBOARD_TOKEN
   npx wrangler secret put AUDIT_INGEST_TOKEN
   ```

6. Deploy with `npm run deploy`.
7. In Cloudflare, attach a route for each alias hostname to this Worker. Each hostname must have a proxied Cloudflare DNS record. All alias routes should use the same `ORIGIN_URL`.
8. Visit `https://your-domain.example.com/_sentinel`, choose **Connect deployment**, and enter the `DASHBOARD_TOKEN`.

Routes can also be kept in Wrangler configuration:

```jsonc
"routes": [
  { "pattern": "example.com/*", "zone_name": "example.com" },
  { "pattern": "www.example.com/*", "zone_name": "example.com" },
  { "pattern": "another-alias.com/*", "zone_name": "another-alias.com" }
]
```

Replace the example hostnames and zone names with the actual Cloudflare zones. See [Cloudflare Workers routes](https://developers.cloudflare.com/workers/configuration/routing/routes/) for route configuration details.

## Send application audit events

Call `POST /api/ingest` from a trusted website backend. Never expose `AUDIT_INGEST_TOKEN` in browser JavaScript.

```js
await fetch("https://www.example.com/api/ingest", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${env.AUDIT_INGEST_TOKEN}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    actor: user.id,
    action: "user.role.updated",
    target: `user:${targetUser.id}`,
    outcome: "success",
    requestId: request.headers.get("x-request-id"),
    metadata: { from: "viewer", to: "editor" }
  })
});
```

`action` is required. `outcome` accepts `success`, `failure`, or `denied`. The request body is limited to 8 KB. Metadata is restricted to up to 20 scalar fields; keys containing `password`, `secret`, `token`, `authorization`, `cookie`, or `credential` are omitted. Avoid sending unnecessary personal or sensitive data.

## Configuration and limitations

`RATE_LIMIT`, `WINDOW_SECONDS`, `RETENTION_HOURS`, and `BLOCK_MODE` are configurable in `wrangler.jsonc`. Defaults are 90 requests per 60-second bucket, 72-hour retention, and detection-only mode.

The detection rules are simple heuristics. Rate counters and event indexes use Workers KV, which is eventually consistent and does not provide atomic counter updates. The dashboard indexes at most 500 audit entries and up to 500 detection IDs, while its detections API returns up to 150 records. Data expires according to `RETENTION_HOURS`. These properties make the project suitable for a recent operational view, not a permanent, tamper-evident, or compliance audit archive. Consider Cloudflare WAF, rate-limiting rules, and a durable database or SIEM for production security and long-term retention.

## Security notes

- Keep `.dev.vars`, dashboard tokens, ingestion tokens, and credentials out of Git.
- Use separate strong values for `DASHBOARD_TOKEN` and `AUDIT_INGEST_TOKEN`.
- Restrict direct access to your origin if all site requests must pass through Cloudflare.
- Review and tune rules in detection-only mode before enabling blocks.
- This project has no license file yet; add a license if you want to grant public reuse rights.
