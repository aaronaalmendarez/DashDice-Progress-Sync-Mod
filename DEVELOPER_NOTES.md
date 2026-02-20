# Developer Notes

This file contains the detailed technical notes that were previously in `README.md`.

## Data Synced
- `levelId`
- `normal` (0-100)
- `practice` (0-100)
- `attempts`
- Optional profile metadata:
  - `gdHasAccount`
  - `gdAccountId`
  - `gdUsername`
  - `gdPlayerName`

## Trigger Points
- `onQuit`
- `levelComplete`

The mod enqueues events and flushes to your sync API endpoint.

## Settings
- `Enable Progress Sync`
- `Sync Endpoint` (example: `http://localhost:3000/api/sync/progress`)
- `API Key` (`Authorization: Bearer <key>`)
- `Request Timeout (s)`
- `Debug Logs`

## Build
1. Set `GEODE_SDK` environment variable.
2. From repo root:
   - `cmake -B build`
   - `cmake --build build --config RelWithDebInfo`
3. Install generated `.geode` into your GD `geode/mods` folder.

## Behavior Notes
- Pending progress events are stored in Geode saved values and retried later.
- If endpoint/API key is missing, queue remains local until configured.
- If no Geometry Dash account is linked, the mod can show a one-time reliability notice.
