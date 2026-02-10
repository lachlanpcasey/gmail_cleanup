# Mass Email Deletion for Promotions

## Overview

This feature allows you to scan your Gmail Promotions category, aggregate emails by sender domain, and mass delete emails from specific domains.

## How It Works

### 1. Database Models

- **PromotionsDomain**: Tracks email count by domain in Promotions
- **PromotionsScanProgress**: Tracks scan progress for the Promotions category

### 2. Scanning Process

The scanner:

- Uses Gmail's `CATEGORY_PROMOTIONS` label to filter emails
- Extracts sender domains from email headers
- Counts emails per domain
- Stores example subjects and sender names
- Supports pagination for large mailboxes

### 3. Deletion Process

- Searches for all messages from a specific domain in Promotions
- Uses Gmail's `batchDelete` API (up to 1000 messages per batch)
- Permanently deletes emails (cannot be undone)
- Removes domain record from database after deletion

## Usage

### Access the Feature

1. Log in to the app
2. Click "🗑️ Mass Delete Promotions" on the home page

### Scan Promotions

1. Click "🔍 Scan Promotions" button
2. Wait for scan to complete (progress bar shows status)
3. View domain statistics with email counts

### Delete Emails from a Domain

1. Find the domain you want to delete
2. Review the email count and example subjects
3. Click "🗑️ Delete All X Emails" button
4. Confirm the deletion
5. Wait for deletion to complete

## Important Notes

### Permissions

- Requires Gmail API access with delete permissions
- Uses OAuth 2.0 authentication

### Safety

- Deletions are **permanent** and cannot be undone
- Always review the domain and email count before deleting
- Confirmation dialog helps prevent accidental deletions

### Performance

- Scanning limit: 1,000 messages per scan (configurable)
- Deletion limit: No limit (batched in groups of 1,000)
- Background tasks prevent UI blocking

### Gmail API Limits

- Respects Gmail API rate limits
- Includes retry logic for transient errors
- Exponential backoff for rate limiting

## API Endpoints

### GET /promotions

Displays the Promotions management page

### POST /start_promotions_scan

Starts a background scan of Promotions category
Returns: `{"ok": true, "message": "promotions_scan_started"}`

### GET /promotions_scan_progress

Gets current scan progress
Returns: `{"ok": true, "is_scanning": bool, "current": int, "total": int, "percent": int}`

### POST /delete_domain_emails

Deletes all emails from a specific domain
Body: `{"domain": "example.com"}`
Returns: `{"ok": true, "message": "deletion_started", "domain": "example.com"}`

## Technical Details

### Gmail Category Labels

- Uses `CATEGORY_PROMOTIONS` label (Gmail's built-in category)
- Other categories available: SOCIAL, UPDATES, FORUMS, PERSONAL

### Search Query Format

```
from:@domain.com category:promotions
```

### Database Schema

```sql
CREATE TABLE promotions_domains (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    domain VARCHAR NOT NULL,
    email_count INTEGER DEFAULT 0,
    sender_name VARCHAR,
    example_subjects JSON,
    last_scanned TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE promotions_scan_progress (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE,
    current_message INTEGER DEFAULT 0,
    estimated_total INTEGER DEFAULT 0,
    is_scanning BOOLEAN DEFAULT FALSE,
    started_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    page_token VARCHAR
);
```

## Future Enhancements

Potential improvements:

- Support for other Gmail categories (Social, Updates, Forums)
- Date range filtering (e.g., delete emails older than X months)
- Whitelist/blacklist domains
- Undo functionality (move to trash instead of permanent delete)
- Export domain statistics to CSV
- Scheduled automatic deletions
- Domain-specific rules (keep emails with certain subjects)

## Troubleshooting

### Scan Not Starting

- Check OAuth permissions include Gmail access
- Verify user is authenticated
- Check database connectivity

### Deletion Fails

- Verify Gmail API quota hasn't been exceeded
- Check network connectivity
- Review app logs for specific errors

### Missing Emails in Count

- Some emails may not have proper sender headers
- Scan limit may be reached before all emails are processed
- Re-run scan to update counts
