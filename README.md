# HYEHOST ContainerTest Node

A clean HYEHOST Bot Hosting test baseline for the ContainerTest project.

## What this version includes

- one lightweight Node.js process; no database and no extra daemon
- static cover page on `/`
- JSON health status on `/health`
- VLESS over WebSocket, TCP outbound
- persistent generated UUID, WS path, subscription token and stable `node_id`
- HYEHOST NAT endpoint learning from the first real public request
- two-source egress-country verification (Cloudflare + ipinfo)
- country-prefixed client remark such as `US-HYEHOST-01`
- local upload/download/connection accounting
- Railway registration and heartbeat
- Railway traffic push when `REGISTRY_TOKEN` is configured
- public-proof fallback registration when no registry token is present
- registration is intentionally gated until a real VLESS TCP connection succeeds
- restart-safe identity and traffic state

## HYEHOST deployment baseline

Use **Node.js 24** for the first clean test.

Set the HYEHOST service to listen on internal port:

```text
8080
```

Map the free NAT port to that internal port. The external NAT port can be different.

Startup command:

```text
npm start
```

No npm packages are required.

HYEHOST currently documents Node.js 22/24/26 support, Git deployment, environment variables, persistent service files, one NAT port and dedicated IPv6 on the free plan.

## Environment variables

Minimal recommended configuration:

```text
PORT=8080
NODE_NAME=HYEHOST-01
REGISTRY_URL=https://subscription-server-v2-production.up.railway.app
```

For the **full Railway traffic app-push path**, also set the existing shared registry credential in the HYEHOST environment:

```text
REGISTRY_TOKEN=<existing Railway registry credential>
```

Do not commit that token.

`UUID`, `WS_PATH`, `SUB_TOKEN`, and `NODE_ID` are optional. If omitted, the service generates them once and persists them under `~/.hyehost-node`.

`PUBLIC_ENDPOINT` should normally remain unset. After deployment, visit the real HYEHOST public NAT URL once. The service learns the public host and external port from that request and prints the final VLESS URL in the console. Only set `PUBLIC_ENDPOINT` if the HYEHOST request headers do not preserve the real public host:port.

## Test order

1. Deploy and start the service.
2. Open the real public NAT URL. `/` must show only the static **Green Horizon / Service is online** cover.
3. Open `/health` and confirm `endpoint_ready=true`.
4. Confirm geo detection. A two-source match gives `geo.verified=true`; otherwise the node keeps `XX`.
5. Copy the final VLESS URL from the HYEHOST console into v2rayN/Shadowrocket.
6. Make a real outbound connection through the node.
7. On the first successful VLESS TCP connection, the node sets `proxy_verified=true` and becomes registry-eligible.
8. Confirm Railway receives the node and traffic.
9. Confirm Railway's independent country verification/rewrite produces the same real country prefix in the final subscription remark.
10. Restart HYEHOST and confirm the same `node_id`, UUID, path, traffic totals and subscription record are retained without duplicate nodes.

## Important status meanings

`/health` deliberately separates:

- `ok`: the Node.js HTTP process is alive.
- `endpoint_ready`: a public endpoint is known.
- `endpoint_confirmed_this_boot`: the public endpoint was actually seen this boot.
- `proxy_verified`: at least one real authenticated VLESS TCP connection has succeeded.
- `registry.eligible`: endpoint + successful proxy validation are both present.
- `registry.registered`: Railway accepted the current registration.

A green cover page or HTTP 200 alone is **not** treated as a working proxy.

## Traffic

The node counts VLESS payload bytes:

- upload: client payload written to the remote TCP socket
- download: remote TCP payload returned to the client
- connections: successful remote TCP connections

The protected tokenized endpoint exposes local counters:

```text
/<SUB_TOKEN>/traffic
```

When `REGISTRY_TOKEN` exists, every heartbeat sends the cumulative counters to Railway using the current registry contract.

Without `REGISTRY_TOKEN`, the node uses the existing public-proof registration path and periodically re-registers. This keeps registration usable, but bearer-token mode is the preferred path for the full central traffic manager.

## Country-code rule

The node does not trust the selected HYEHOST region. It checks the actual egress network using two independent sources. Only a matching result is marked verified.

The Railway manager remains the second authority: it should independently test the node/egress location and rewrite the displayed subscription remark if the node-side claim is missing or wrong. The HYEHOST payload provides `metadata.location`, `metadata.egress_ip`, and `metadata.country_verified` for that comparison.

## Security

The public root page never exposes UUID, WS path, Railway credentials, subscription token, or proxy URI. Operator details are stored in:

```text
~/.hyehost-node/operator.json
```

and are also printed to the private HYEHOST console after the public endpoint is learned.

Never commit the Railway registry token.
