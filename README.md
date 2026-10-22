# VYBE — FIND YOUR VIBE

VYBE is a people-based profile directory for discovering individuals by shared interests and general location. Profiles and edits require administrator review. Contact details are private unless the profile owner chooses to show them. The app uses Python's standard library, SQLite, and a responsive browser interface; no third-party packages are required.

## Start the app

- Python 3.10 or newer
- Run `python seed.py` to load fictional development data.
- Run `python server.py` and open [http://127.0.0.1:8004](http://127.0.0.1:8004). Use [http://127.0.0.1:8004/admin](http://127.0.0.1:8004/admin) to go straight to admin sign-in.
- `npm start` is available as a convenience when Python is on PATH.

SQLite data lives in `data/nightlife.db`. Stop the server before deleting that file to reset the database, then rerun the seed command. The seed loader is repeatable and intended for local development.

## Demo accounts

Demo customer and provider accounts use `EmpireDemo!2026` locally:

- Admin: the protected administrator created for this local installation; its login address is intentionally not listed here.
- Customers: `customer1@nightlife.test` through `customer5@nightlife.test`
- Profile owners: `provider1@nightlife.test` through `provider8@nightlife.test`
- Pending applications: `pending1@nightlife.test`, `pending2@nightlife.test`

Demo names, biographies, images and contact details are fictional. Do not use these credentials in production.

## Administrator accounts

- The first active administrator in an installation becomes the **protected owner** and overall admin. Keep this account's email and password available to the site owner.
- The protected owner cannot be deleted, suspended, or demoted through the admin API or directly from SQLite. Other overall admins can create and manage the rest of the admin team but cannot change the protected owner's account.
- Passwords use salted scrypt hashes. Admin passwords must be at least 12 characters and use a mix of character types. Admin sign-in supports optional TOTP multi-factor authentication.
- Other administrators have the same day-to-day moderation powers (applications, profiles, reviews, VIP, reports, catalog and settings) but cannot view or manage the admin team.
- Every admin-team action is recorded in the administrator audit trail.

## Provider approvals

1. A provider can register and open their dashboard while their account and profile are pending.
2. Providers can submit and edit profile details without a payment or subscription check. Suspended or rejected accounts cannot submit.
3. The administrator reviews the application. **Approve & publish** activates the provider and publishes any submitted profile publicly, including to visitors who are not signed in. New edits return to review.
4. Admins can suspend or reactivate provider and customer accounts. Customer reviews remain moderated. Phone and WhatsApp appear only when the provider chooses to show them.

## Database

SQLite tables cover users, provider applications, individual profiles and profile media, customer-provider messages, customer reviews, legacy listing records, reports, settings, and the administrator audit trail. VYBE no longer reads or writes legacy subscription or VIP payment-request records; any such historical records in an existing database are left untouched. Administrators can edit the service and location menus, moderate reviews, and manage public featured-provider placement. VIP is a membership tier controlled by the administrator. VIP-only (featured) profiles are hidden from standard and signed-out visitors, and only active VIP members can open, save, message, review or report them. Customers request VIP from the VIP page; administrators activate, suspend, renew and set expiry from the VIP management dashboard, and every membership change is recorded in the membership history. Expired memberships fall back to the standard account automatically and can be renewed. VIP price and duration are configured in admin settings (defaults: UGX 150,000 for 30 days; no payment provider is integrated, so activation is manual). Passwords are salted scrypt hashes. Profile image uploads accept PNG, JPEG and WebP files up to 5 MB each, up to 10 photos. Profile videos accept MP4, WebM and MOV files up to 20 MB each, up to two videos. Uploaded images and videos require an ownership or consent confirmation. Customer accounts do not have public profile photos. Demo portraits use Unsplash photo URLs; replace them with media you have permission to publish before launch.

## Hosting and production limits

The server accepts `PORT` (or `VYBE_PORT`) and `VYBE_HOST` environment variables. It defaults to `127.0.0.1:8004` locally and binds to `0.0.0.0` in production unless the host supplies `VYBE_HOST`. `VYBE_DATA_DIR` can point to a persistent writable mount for SQLite; `VYBE_MEDIA_DIR` can separately point to persistent upload storage. It is a small Python standard-library server, not a production application server; put it behind a host-provided HTTPS proxy and confirm the host supports persistent writable storage before using it for real accounts.

Sessions are stored in the SQLite database, so they survive a server restart only if the database file survives. Uploaded media is stored under `media/`, so it also needs persistent storage and backups. Login and password-reset throttling currently lives in process memory: it resets when the process restarts and is not shared between multiple server instances. Email delivery is not configured, so password recovery and notifications need an email provider. Set `VYBE_ENV=production` only when requests reach the app through HTTPS; this enables Secure cookies and HSTS.

The app does not yet provide automated off-site backups, uptime monitoring, or malware scanning. Do not publish development seed data or the local database. The first admin account becomes a protected owner, but the hosting account owner can still change or delete the app's files and database; keep hosting access and backups protected separately. Admins can suspend or reactivate customer and provider accounts. Customer-provider messages are available only to signed-in, active accounts.

## Checks

Run `python -m py_compile server.py seed.py` and `node --check app.js` for syntax checks. `python seed.py` is for local development only and refuses to run when `VYBE_ENV=production`. With a development server running, `test_security_e2e.py`, `test_admin_messaging_e2e.py`, and `test_vip_e2e.py` exercise security, owner/admin protections, messaging, and VIP access. The security test expects the server on port 8011 and `VYBE_DEV_RESET_LINK=1` so password-recovery can be tested without email delivery.

