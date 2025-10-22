# SL Bus Timetable

A Node.js + SQLite application that serves a unified API for the Sri Lanka expressway bus timetable and three HTML front-ends:

* `index.html` – public journey search experience powered entirely by the REST API.
* `admin.html` – secure admin console for CRUD, ordering and bulk creation of buses.
* `timekeeper.html` – depot-focused dashboard for live status updates and unscheduled runs.
* `user_management.html` – admin-only provisioning UI for timekeepers and additional admins.

## Prerequisites

* Node.js 18+
* npm

The repository ships with a `timetable.db` SQLite database and a fallback `buses.json` seed. The server will create missing tables/columns automatically.

## Configuration

Copy `.env.example` to `.env` and adjust the values as required:

```env
PORT=3000
JWT_SECRET=super-secret-string
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=password
LEGACY_ADMIN_USERNAME=admin
LEGACY_ADMIN_PASSWORD=password
TIMEKEEPER_EMAIL=timekeeper@example.com
TIMEKEEPER_PASSWORD=password
TIMEKEEPER_DEPOT=Makumbura
LEGACY_TIMEKEEPER_USERNAME=timekeeper
```

The secret values are used to provision the first admin, a default timekeeper, and to sign authentication tokens. When the `users` table is empty the server will create the admin account using `ADMIN_EMAIL`/`ADMIN_PASSWORD` and a timekeeper at `TIMEKEEPER_EMAIL`.

> **Quick start credentials:**
> * Admin – `admin@example.com` / `password` (username `admin` also works)
> * Timekeeper – `timekeeper@example.com` / `password` (username `timekeeper`)

## Installation

```bash
npm install
```

> If you are running in an offline or restricted environment you can skip this step because the repository already contains a `node_modules` directory with the required packages (`express`, `cors`, and `better-sqlite3`).

## Running the server

```bash
npm start
```

The server listens on `http://localhost:3000` by default and exposes:

* `/api/login` – obtain a short-lived token using email/password.
* `/api/search` – public search endpoint consumed by `index.html`.
* `/api/buses` and related endpoints – protected admin CRUD.
* `/api/timekeeper/...` – endpoints for depot dashboards.
* `/api/users` – admin-only provisioning API.

Static files are served from the repository root, so visiting `/`, `/admin.html`, `/timekeeper.html` or `/user_management.html` in the browser will load the respective UI.

## Authentication flow

1. Admins and timekeepers sign in via `/api/login`.
2. The backend issues a signed JWT-like token using the configured `JWT_SECRET`.
3. Subsequent requests include `Authorization: Bearer <token>` headers.
4. `admin.html`, `user_management.html`, and `timekeeper.html` store the token in `localStorage` and automatically refresh their data.

Tokens expire after one hour; the front-ends handle 401 responses by redirecting back to the login screen.

## Database schema

The server auto-migrates the following tables:

* `buses`
  * Core timetable (route/operator/origin/destination/times)
  * JSON columns for `stops` and `availability`
  * Status tracking (`Scheduled`, `Departed`, `Arrived`, `Delayed`, `Cancelled`)
  * Sort order plus audit timestamps
* `users`
  * Email + role (`admin` or `timekeeper`)
  * Optional depot assignment
  * Passwords hashed via `crypto.scrypt`

## Testing the API

With the server running you can quickly verify endpoints using `curl`:

```bash
curl "http://localhost:3000/api/search?from=makumbura&to=galle&date=2024-10-01"
```

To authenticate:

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin@example.com","password":"password"}' | jq -r '.token')

curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/buses
```

## Deployment notes

* Treat `.env` secrets carefully – inject them during deployment instead of committing real values.
* The static HTML files expect the API to be hosted on the same origin. If you deploy the backend separately, either proxy the API or adjust the fetch calls to point at the deployed origin.
* Back up `timetable.db` regularly; the admin tools modify it directly.

## Troubleshooting

* **Cannot login:** try the default credentials (`admin@example.com` / `password` or `timekeeper@example.com` / `password`). Delete `timetable.db` to trigger the seed using the values from your `.env` file if you have customised them.
* **Search returns nothing:** confirm you imported data (`buses.json`) and that the `availability` array contains the day you are querying.
* **403/401 errors in admin UI:** tokens expire after one hour. Log out and sign back in to obtain a fresh token.

## License

MIT
