"""
Migration script to add emails_deleted column to users table.
Run this once if you have an existing database.
"""

from app.db import SessionLocal, engine
from sqlalchemy import Column, Integer, text


def migrate():
    """Add emails_deleted column to users table if it doesn't exist."""
    db = SessionLocal()
    try:
        # Check if column exists
        result = db.execute(text("PRAGMA table_info(users)"))
        columns = [row[1] for row in result.fetchall()]

        if 'emails_deleted' not in columns:
            print("Adding emails_deleted column to users table...")
            db.execute(
                text("ALTER TABLE users ADD COLUMN emails_deleted INTEGER DEFAULT 0"))
            db.commit()
            print("✅ Migration complete: emails_deleted column added")
        else:
            print("✅ Column emails_deleted already exists, no migration needed")

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
