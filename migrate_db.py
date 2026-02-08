"""
Database migration script to add new columns for incremental scanning feature.
Run this once to update your existing database schema.
"""
import sqlite3
import os

db_path = "./gmail_cleanup.db"

if not os.path.exists(db_path):
    print(f"Database not found at {db_path}. No migration needed.")
    exit(0)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Check if columns exist before adding them
    print("Checking database schema...")

    # Add last_scan_date to users table
    try:
        cursor.execute("SELECT last_scan_date FROM users LIMIT 1")
        print("✓ users.last_scan_date already exists")
    except sqlite3.OperationalError:
        print("Adding last_scan_date column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN last_scan_date TIMESTAMP")
        print("✓ Added users.last_scan_date")

    # Add new_subscriptions_found to scan_progress table
    try:
        cursor.execute(
            "SELECT new_subscriptions_found FROM scan_progress LIMIT 1")
        print("✓ scan_progress.new_subscriptions_found already exists")
    except sqlite3.OperationalError:
        print("Adding new_subscriptions_found column to scan_progress table...")
        cursor.execute(
            "ALTER TABLE scan_progress ADD COLUMN new_subscriptions_found INTEGER DEFAULT 0")
        print("✓ Added scan_progress.new_subscriptions_found")

    # Add total_messages_scanned to scan_progress table
    try:
        cursor.execute(
            "SELECT total_messages_scanned FROM scan_progress LIMIT 1")
        print("✓ scan_progress.total_messages_scanned already exists")
    except sqlite3.OperationalError:
        print("Adding total_messages_scanned column to scan_progress table...")
        cursor.execute(
            "ALTER TABLE scan_progress ADD COLUMN total_messages_scanned INTEGER DEFAULT 0")
        print("✓ Added scan_progress.total_messages_scanned")

    conn.commit()
    print("\n✅ Migration completed successfully!")

except Exception as e:
    conn.rollback()
    print(f"\n❌ Migration failed: {e}")
    raise
finally:
    conn.close()
