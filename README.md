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
- **Data Source**: BMW Connected Drive API via Google Apps Script bridge
- **Domain**: [bmw.samuelecorona.it](https://bmw.samuelecorona.it)

## Integration

The `/fuel` page links to [carburanti.samuelecorona.it](https://carburanti.samuelecorona.it) for real-time Italian fuel price comparison using MIMIT Open Data.

## Deployment

```bash
npx wrangler deploy
```

## License

Private project by Samuele Corona.
