"""
Migration script to add category column to promotions tables.
Run this once if you have an existing database.
"""

from app.db import SessionLocal
from sqlalchemy import text


def migrate():
    """Add category column to promotions_domains and promotions_scan_progress tables."""
    db = SessionLocal()
    try:
        # Check and add category to promotions_domains
        result = db.execute(text("PRAGMA table_info(promotions_domains)"))
        columns = [row[1] for row in result.fetchall()]

        if 'category' not in columns:
            print("Adding category column to promotions_domains table...")
            db.execute(text(
                "ALTER TABLE promotions_domains ADD COLUMN category TEXT DEFAULT 'promotions'"))
            db.execute(text(
                "UPDATE promotions_domains SET category = 'promotions' WHERE category IS NULL"))
            print("✅ Added category to promotions_domains")
        else:
            print("✅ Column category already exists in promotions_domains")

        # Check and add category to promotions_scan_progress
        result = db.execute(
            text("PRAGMA table_info(promotions_scan_progress)"))
        columns = [row[1] for row in result.fetchall()]

        if 'category' not in columns:
            print("Adding category column to promotions_scan_progress table...")
            db.execute(text(
                "ALTER TABLE promotions_scan_progress ADD COLUMN category TEXT DEFAULT 'promotions'"))
            db.execute(text(
                "UPDATE promotions_scan_progress SET category = 'promotions' WHERE category IS NULL"))
            # Drop unique constraint on user_id since we now have user_id+category combinations
            print(
                "Note: You may need to recreate the table to remove unique constraint on user_id")
            print("✅ Added category to promotions_scan_progress")
        else:
            print("✅ Column category already exists in promotions_scan_progress")

        db.commit()
        print("\n✅ Migration complete!")

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
