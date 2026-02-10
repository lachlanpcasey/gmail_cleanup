"""
Migration script to fix unique constraint on promotions_scan_progress table.
Changes from unique(user_id) to unique(user_id, category).
"""
import sqlite3
from pathlib import Path

# Get database path
db_path = Path(__file__).parent / "gmail_cleanup.db"

print(f"Fixing unique constraint in {db_path}")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Create new table with correct schema
    print("Creating new table with composite unique constraint...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS promotions_scan_progress_new (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL DEFAULT 'promotions',
            current_message INTEGER DEFAULT 0,
            estimated_total INTEGER DEFAULT 0,
            is_scanning INTEGER DEFAULT 0,
            started_at TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            page_token TEXT,
            UNIQUE(user_id, category)
        )
    """)

    # Copy data from old table to new table
    print("Copying existing data...")
    cursor.execute("""
        INSERT INTO promotions_scan_progress_new 
            (id, user_id, category, current_message, estimated_total, 
             is_scanning, started_at, updated_at, page_token)
        SELECT id, user_id, category, current_message, estimated_total,
               is_scanning, started_at, updated_at, page_token
        FROM promotions_scan_progress
    """)

    # Drop old table
    print("Dropping old table...")
    cursor.execute("DROP TABLE promotions_scan_progress")

    # Rename new table to original name
    print("Renaming new table...")
    cursor.execute(
        "ALTER TABLE promotions_scan_progress_new RENAME TO promotions_scan_progress")

    # Create indexes
    print("Creating indexes...")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS ix_promotions_scan_progress_user_id ON promotions_scan_progress(user_id)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS ix_promotions_scan_progress_category ON promotions_scan_progress(category)")

    conn.commit()
    print("✅ Migration complete! Unique constraint is now on (user_id, category)")

except Exception as e:
    conn.rollback()
    print(f"❌ Error during migration: {e}")
    raise
finally:
    conn.close()
