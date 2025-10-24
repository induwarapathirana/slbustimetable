# SL Bus Timetable

A Firebase-backed toolkit for managing and sharing Sri Lanka expressway bus schedules. The project ships three role-based single-page apps — a public search portal, an admin console, and a timekeeper dashboard — that all talk directly to the same Firestore database and reuse Firebase Authentication for sign-in.

## Project structure

```
slbustimetable/
├── index.html             # Passenger search experience
├── admin.html             # Admin console for managing buses and fare presets
├── timekeeper.html        # Depot timekeeper console with day-specific controls
├── user_management.html   # Helper screen for reviewing role assignments
├── firebase.json          # Firebase Hosting / emulator configuration
├── server.js              # Optional legacy SQLite API (not required when using Firebase)
├── buses.json             # Example data set used by the legacy API
└── package.json           # Convenience scripts for local hosting
```

Only the HTML files are required when hosting on Firebase or any static host. The Node/SQLite server is kept for historical reference and can be ignored when working with the Firebase backend.

## 1. Configure Firebase

1. Create (or reuse) a Firebase project with Authentication and Cloud Firestore enabled.
2. Add Web App credentials from the Firebase console and copy the `firebaseConfig` object.
3. Paste the config into the following files, replacing the existing placeholder values:
   - `index.html`
   - `admin.html`
   - `timekeeper.html`
   - `user_management.html`
4. If you prefer to keep secrets out of version control, extract the config into `firebase-config.js` and include it before the inline scripts in each page.

### Authentication setup

* Enable **Email/Password** sign-in.
* Create users for each operator from the Firebase console (or via your existing onboarding workflow).
* In Cloud Firestore, create a `users/{uid}` document for every authenticated user and add a `role` field with one of:
  * `admin` – full access to `admin.html` and `user_management.html`
  * `timekeeper` – access to `timekeeper.html`
* Optionally store extra profile data (e.g., `depot`) on the same document. The timekeeper console reads a `depot` string to limit schedules to a single depot.

### Firestore collections used by the UI

| Collection | Purpose | Key fields |
|------------|---------|------------|
| `buses` | Master timetable data. Created/edited by admins, read by all apps. | `route`, `operator`, `departsFrom`, `arrivesAt`, `departureTime`, `arrivalTime`, `price`, `availability` (array of weekdays), `stops` (array of strings), `sortOrder` (number), `status`, `specialDates` (array of ISO `YYYY-MM-DD` strings when the bus runs outside its weekly pattern).
| `priceMatrix` | Fare presets that feed autocomplete across forms. | `origin`, `destination`, `price`, `updatedAt`, `updatedBy` |
| `busStatusOverrides` | Day-specific status changes created by timekeepers. | `busId`, `date` (ISO string), `depot`, `status`, `updatedAt`, `updatedBy` |
| `users` | Role metadata for authenticated users. | `email`, `role`, `depot` |

> 💡 Existing data created before this update will continue to work. The new collections (`priceMatrix` and `busStatusOverrides`) are optional – the UI simply shows empty states until entries are created.

## 2. Local development options

### Firebase Hosting / emulators (recommended)

```bash
npm install
npm run dev        # runs firebase emulators:start with hosting, auth, and firestore
```

This serves all HTML files at `http://localhost:5000` using the Firebase emulators defined in `firebase.json`. The emulated services let you test authentication, Firestore rules, and the UI without touching production data.

### Static preview without Firebase

If you only need a static preview of the markup, you can open the HTML files directly in a browser. The Firebase SDK will report a configuration error until valid credentials are supplied.

### Legacy Express/SQLite API (optional)

The original Gemini prototype also shipped with a simple Express server (`server.js`) that reads from `timetable.db`. This backend is no longer required for the Firebase workflow, but the code remains in case you need to migrate data from SQLite or run load tests. Start it with:

```bash
npm install
npm start
```

## 3. Feature overview

### Admin console (`admin.html`)

* Email/password login via Firebase Authentication.
* Real-time timetable table with drag-and-drop ordering (powered by SortableJS).
* Modal forms for single bus CRUD and frequency-based bulk creation.
* Price matrix management: curate origin/destination pairs once and auto-fill fare inputs everywhere.
* Location suggestions shared with timekeepers and passengers.

### Timekeeper console (`timekeeper.html`)

* Depot-specific view filtered by the signed-in user’s `depot` value.
* Day picker with live schedules sourced from the shared `buses` collection.
* Status buttons (“Scheduled”, “Departed”, “Arrived”, “Delayed”, “Cancelled”) that write to `busStatusOverrides` for the selected date only.
* Support for creating either temporary (single-day) or permanent buses with the same detail form used by admins.
* Fare and location auto-complete backed by the shared price matrix.

### Passenger search (`index.html`)

* Modern glassmorphism interface with responsive design, reduced-motion support, and accessible live updates.
* Autocomplete suggestions for origin/destination based on existing buses and price presets.
* Date-aware filtering that merges base schedules with any single-day services or overrides.
* Highlighting of the next upcoming departure and collapsible stop previews.

### User management helper (`user_management.html`)

* Simple list of Firestore `users` documents so admins can verify assigned roles and depots.
* Guidance for manually creating or removing Firebase Authentication accounts (the UI does not call privileged admin APIs).

## 4. Security rules checklist

To keep production data safe, ensure your Firestore rules enforce role-based access. Example (simplified) rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function isSignedIn() {
      return request.auth != null;
    }

    function isAdmin() {
      return isSignedIn() && get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }

    function isTimekeeper() {
      return isSignedIn() && get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'timekeeper';
    }

    match /buses/{busId} {
      allow read: if true;                       // Public timetable
      allow write: if isAdmin();                 // Admin + timekeeper creation uses callable rules if desired
    }

    match /priceMatrix/{docId} {
      allow read: if isSignedIn();
      allow write: if isAdmin();
    }

    match /busStatusOverrides/{docId} {
      allow read: if isSignedIn();
      allow write: if isTimekeeper();
    }

    match /users/{userId} {
      allow read: if isAdmin();
      allow write: if isAdmin() && userId == request.auth.uid;
    }
  }
}
```

Adjust the rules to fit your exact requirements, especially if you need timekeepers to create temporary buses or if you expose extra admin-only metadata.

## 5. Migrating existing data

* **Buses:** The UI reads existing `buses` documents as-is. To take advantage of drag-and-drop ordering, add a numeric `sortOrder` field (0-based). If omitted, Firestore will store `null` and the UI still renders but drag-and-drop won’t persist order.
* **Statuses:** Legacy `status` fields remain respected. Day-specific overrides are optional and stored separately.
* **Fare presets:** Populate the new `priceMatrix` collection manually or via the admin UI to unlock autocomplete.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Login form loops or shows “Access Denied” | No `users/{uid}` document or missing `role` field | Create the doc with the correct role value (`admin` or `timekeeper`). |
| Price suggestions never appear | No documents in `priceMatrix` or Firestore rules block reads | Add entries via the admin price matrix card and verify Firestore rules. |
| Timekeeper status buttons do nothing | Missing write access to `busStatusOverrides` | Update Firestore rules to allow timekeeper role writes. |
| Passenger page says “Configuration Error” | Firebase config not supplied | Paste the correct config into all HTML files or include a shared config script. |

## 7. Deployment

Deploy the project using any static host (Firebase Hosting, Netlify, Vercel, etc.). For Firebase Hosting:

```bash
firebase login
firebase init hosting   # choose "Use existing project" and select your Firebase project
firebase deploy --only hosting
```

Once deployed, all three role-based apps (admin, timekeeper, user management) and the public search page will connect to the same Firebase backend, so the users you already created can continue to sign in with their original credentials.

---

Questions or suggestions? File an issue or reach out — happy to help keep the buses running on time!
