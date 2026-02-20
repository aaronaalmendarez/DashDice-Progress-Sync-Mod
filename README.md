# DashDice Progress Sync Mod

This Geode mod sends level progress updates to your DashDice server.

## What It Syncs

- `levelId`
- `normal` (0-100)
- `practice` (0-100)
- `attempts`

The mod captures data when you leave a level (`onQuit`) and on completion (`levelComplete`), then pushes queued events to your API endpoint.

It also sends optional profile metadata when available:
- `gdHasAccount`
- `gdAccountId`
- `gdUsername`
- `gdPlayerName`

If no Geometry Dash account is linked, the mod shows a one-time notice recommending account login for better sync reliability.

## Settings

- `Enable Progress Sync`
- `Sync Endpoint` (example: `http://localhost:3000/api/sync/progress`)
- `API Key` (`Authorization: Bearer <key>`)
- `Request Timeout (s)`
- `Debug Logs`

## Build

1. Set `GEODE_SDK` environment variable.
2. From this folder:
   - `cmake -B build`
   - `cmake --build build --config RelWithDebInfo`
3. Install generated `.geode` into your GD `geode/mods` folder.

## Notes

- Pending progress events are stored in Geode saved values and retried when menu initializes.
- If endpoint/API key is missing, queue remains local until configured.
