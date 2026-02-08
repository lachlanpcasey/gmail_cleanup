#!/usr/bin/env python3
"""Reset scan state for a user to start fresh with new scanning logic"""

from app.db import SessionLocal
from app.models import User, ScanProgress, SubscriptionMessage, SubscriptionGroup

db = SessionLocal()

# Get the user
user = db.query(User).filter(User.email == "casematta@gmail.com").first()
if not user:
    print("User casematta@gmail.com not found")
    db.close()
    exit()

print(f"Found user: {user.email}")
print(f"Current last_scan_date: {user.last_scan_date}")

print(f"\nResetting scan state...")
print("Setting last_scan_date to None (new logic relies on thread ID tracking, not dates)")

# Clear the last scan date - we don't use date filtering anymore
user.last_scan_date = None
db.commit()

# Clear scan progress
scan_progress = db.query(ScanProgress).filter(
    ScanProgress.user_id == user.id).first()
if scan_progress:
    scan_progress.current_message = 0
    scan_progress.estimated_total = 0
    scan_progress.is_scanning = False
    scan_progress.total_messages_scanned = 0
    scan_progress.new_subscriptions_found = 0
    db.commit()
    print("Reset scan progress")

# Remove duplicate subscription messages (keep only the earliest one per thread per group)
print("\nRemoving duplicate messages...")
messages = db.query(SubscriptionMessage).join(
    SubscriptionGroup, SubscriptionMessage.group_id == SubscriptionGroup.id
).filter(
    SubscriptionGroup.user_id == user.id
).order_by(SubscriptionMessage.created_at).all()

# Track which thread+group combinations we've seen
seen_combos = set()
to_delete = []

for msg in messages:
    combo = (msg.gmail_thread_id, msg.group_id)
    if combo in seen_combos:
        to_delete.append(msg)
    else:
        seen_combos.add(combo)

print(f"Found {len(to_delete)} duplicate messages to remove")
for msg in to_delete:
    db.delete(msg)
db.commit()

print("\nDone! Database has been reset.")
print("Next scan will process all emails, skipping only the threads already in the database.")
print("Each scan will progressively work through your mailbox until all emails are processed.")

db.close()
