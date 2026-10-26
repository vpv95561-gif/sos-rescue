# RoadRescue

RoadRescue is a local roadside-assistance prototype with a customer booking flow, request tracking, an admin portal, and a workshop vendor portal.

## Run locally

Use Python 3.10 or later from this folder:

```powershell
python server.py
```

Open `http://127.0.0.1:8000`. The app creates `roadrescue.sqlite3` beside `server.py` on first startup. Keep that file to preserve admin accounts, vendor applications, subscriptions, workshop listings, and jobs.

## Neon MCP for VS Code

The workspace configures the hosted Neon MCP server in `.vscode/mcp.json`. Open GitHub Copilot Chat in Agent mode and authorize the Neon OAuth prompt to connect your Neon account. This enables the coding assistant to work with Neon; it does not change the app's SQLite database.

## First-time setup

1. Open `/portal.html` and create the first administrator account. Admin setup is disabled after the first admin is created.
2. Enroll a workshop from the portal. The vendor can sign in immediately, but needs admin approval before requesting a listing plan.
3. The vendor requests a subscription plan and arranges payment offline.
4. After confirming payment, the admin activates the subscription. The vendor can then edit the workshop listing and switch online to receive and accept open jobs, or offline to pause.
5. An accepted vendor sees customer contact details. Customers can view acceptance and completion in the request tracker.

Admins can review vendor contact/profile details, subscription status, customer contact details, request history, and job status. They can also switch an eligible partner online or offline. Vendors must be approved, subscribed, and online before open jobs are shown or can be accepted. Vendors are switched offline when they sign out.

Workshop directory entries require admin approval, an active 30-day subscription, and an enabled workshop listing.

## Permanent administrator access

A permanent administrator account is available for local access:

- Email/username: `admin@roadrescue.com` or `ADMIN`
- Password: `Admin@!23`

Override these with `ROADRESCUE_ADMIN_EMAIL`, `ROADRESCUE_ADMIN_PASSWORD`, and `ROADRESCUE_ADMIN_NAME` environment variables. The account is created on first admin sign-in and can access all admin endpoints. Admin and vendor sign-in are separate: `/api/admin/login` and `/api/vendor/login`. Vendor sign-out is available at `/api/vendor/logout`.

Passwords are hashed and portal sessions use HTTP-only cookies. The app binds to `127.0.0.1` by default and is intended for local testing. Before public deployment, use HTTPS, a production-grade web server, backups, rate limiting, account recovery, email verification, and operational monitoring. Subscription payment confirmation is manual; no payment gateway, SMS, WhatsApp API, live dispatch network, or live technician GPS is connected. Map tiles require an internet connection.
## Deploy online with Neon Postgres

1. Create a Neon project and copy its connection string.
2. Set `DATABASE_URL` to the Neon connection string (`postgresql://...?sslmode=require`).
3. Install dependencies: `pip install -r requirements.txt`
4. Run locally: `python server.py`
5. Deploy to Render/Railway/Heroku using the included `Procfile` (`web: python server.py`).
6. Set `PORT`, `DATABASE_URL`, and admin env vars in the hosting dashboard.