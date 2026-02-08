# Gmail Cleanup

A tool to help you unsubscribe from unwanted email subscriptions.

## Features

- 🔍 Scans your Gmail inbox for subscription emails (up to 500 emails per scan)
- 📊 Groups subscriptions by sender domain
- ✅ One-click unsubscribe via HTTPS unsubscribe links
- 📈 Tracks successful and failed unsubscribe attempts
- ⚡ Incremental scanning - only checks new emails on subsequent scans
- 🔐 Secure OAuth2 authentication with persistent login

## Incremental Scanning

After your first scan, the app remembers when you last scanned and only checks emails received after that date. This means:

- Faster subsequent scans
- No duplicate processing of old emails
- Clear notification if no new subscriptions are found

## Database Migration

If you're upgrading from a previous version, run the migration script to add the new columns:

```bash
python migrate_db.py
```

This will add support for incremental scanning to your existing database.
