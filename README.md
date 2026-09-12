# HYEHOST service test

Small Node.js service used for the current HYEHOST runtime and Railway integration test.

## HYEHOST settings

- Runtime: Node.js 24
- Internal port: 8080
- Repository worktree: `/files`
- Startup command: `exec node /files/index.js`

Do not use `npm start` from the default `/app` working directory: HYEHOST stores the connected Git worktree under `/files`.

## Public routes

- `/` — static cover page
- `/health` — service state only

Private access information is not printed to the console. It is persisted under the service state directory in `operator.json` after the public route is known.

## State

Default state directory:

```text
~/.hyehost-node
```

Identity, route information, counters and validation state are retained there across normal restarts.

## Optional environment values

No environment values are required for the first deployment. Optional settings are documented in `.env.example`.

## First-run sequence

1. HYEHOST starts `/files/index.js` on port 8080.
2. A request through the assigned public address confirms the current route.
3. Two external location sources are compared before a two-letter country prefix is treated as verified.
4. A real client data session must succeed before the service becomes eligible for Railway synchronization.
5. Counters and the stable instance ID are retained across restarts.

The HYEHOST region or host name is not used as the country authority. The observed outbound address is checked independently.
