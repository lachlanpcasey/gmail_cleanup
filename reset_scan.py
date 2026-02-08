"""Reset last_scan_date to force a complete fresh scan"""
from app.db import SessionLocal
from app.models import User

db = SessionLocal()
try:
    user = db.query(User).first()
    if user:
        user.last_scan_date = None
        db.commit()
        print(f"✓ Reset scan date for user {user.email}")
        print("Next scan will process all emails from scratch")
    else:
        print("No user found in database")
finally:
    db.close()
