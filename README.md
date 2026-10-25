# RoadRescue

RoadRescue is a local roadside-assistance prototype with a customer booking flow, request tracking, an admin portal, and a workshop vendor portal.

## Run locally

Use Python 3.10 or later from this folder:

```powershell
python server.py
```

Open `http://127.0.0.1:8000`. The app creates `roadrescue.sqlite3` beside `server.py` on first startup. Keep that file to preserve admin accounts, vendor applications, subscriptions, workshop listings, and jobs.

## First-time setup

1. Open `/portal.html` and create the first administrator account. Admin setup is disabled after the first admin is created.
2. Enroll a workshop from the portal. The vendor can sign in immediately, but needs admin approval before requesting a listing plan.
3. The vendor requests a subscription plan and arranges payment offline.
4. After confirming payment, the admin activates the subscription. The vendor can then edit the workshop listing and switch online to receive and accept open jobs, or offline to pause.
5. An accepted vendor sees customer contact details. Customers can view acceptance and completion in the request tracker.

Admins can review vendor contact/profile details, subscription status, customer contact details, request history, and job status. They can also switch an eligible partner online or offline. Vendors must be approved, subscribed, and online before open jobs are shown or can be accepted. Vendors are switched offline when they sign out.

Workshop directory entries require admin approval, an active 30-day subscription, and an enabled workshop listing.

## Prototype boundaries

Passwords are hashed and portal sessions use HTTP-only cookies. The app binds to `127.0.0.1` by default and is intended for local testing. Before public deployment, use HTTPS, a production-grade web server, backups, rate limiting, account recovery, email verification, and operational monitoring. Subscription payment confirmation is manual; no payment gateway, SMS, WhatsApp API, live dispatch network, or live technician GPS is connected. Map tiles require an internet connection.