# BMW X3 M40d Dashboard

Cloudflare Worker + D1 dashboard for BMW X3 M40d vehicle data tracking.

## Features

- **Vehicle Info**: Real-time vehicle status and specifications
- **Trips**: Journey tracking with distance, consumption, and route data
- **Fuel**: Refueling history, consumption charts, and diesel price tracking
- **Locations**: GPS position history on interactive map
- **History**: Daily data log with all vehicle metrics

## Architecture

- **Runtime**: Cloudflare Workers (serverless JavaScript)
- **Database**: Cloudflare D1 (SQLite-compatible)
- **Data Source**: BMW CarData direct OAuth/REST foundation, with Home Assistant/Google bridge retained temporarily during migration
- **Domain**: [bmw.samuelecorona.it](https://bmw.samuelecorona.it)

## Integration

The `/fuel` page links to [carburanti.samuelecorona.it](https://carburanti.samuelecorona.it) for real-time Italian fuel price comparison using MIMIT Open Data.

## Deployment

```bash
npx wrangler deploy
```

## License

Private project by Samuele Corona.


## Direct BMW CarData migration

The Worker now contains the first stage of a direct BMW CarData path:

```text
BMW CarData OAuth/REST -> Cloudflare Worker -> D1 -> dashboard
```

The existing Home Assistant / Google ingestion remains untouched during validation.

Required Worker runtime settings (do not commit their values):

- `BMW_CLIENT_ID`
- `BMW_VIN`
- `BMW_TOKEN_ENCRYPTION_KEY` (secret, used to AES-GCM encrypt OAuth tokens at rest in D1)
- optional `BMW_CONTAINER_ID` for the telematicData REST container

Authenticated admin endpoints:

- `GET /api/bmw-direct/status`
- `POST /api/bmw-direct/device/start`
- `POST /api/bmw-direct/device/poll`
- `POST /api/bmw-direct/refresh`
- `POST /api/bmw-direct/fetch`

A cron trigger runs every four hours. Until runtime settings and OAuth authorization are present, it exits without changing existing dashboard data.
