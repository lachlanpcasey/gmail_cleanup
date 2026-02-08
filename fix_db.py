import sqlite3

conn = sqlite3.connect('gmail_cleanup.db')
cursor = conn.cursor()

print("Updating all subscription groups to set unsubscribed = 0...")
cursor.execute(
    "UPDATE subscription_groups SET unsubscribed = 0 WHERE unsubscribed = 1")
affected = cursor.rowcount
conn.commit()

print(f"Updated {affected} rows")

# Verify
groups = cursor.execute(
    "SELECT COUNT(*) FROM subscription_groups WHERE unsubscribed = 0").fetchone()
print(f"Groups with unsubscribed = 0: {groups[0]}")

groups_total = cursor.execute(
    "SELECT COUNT(*) FROM subscription_groups").fetchone()
print(f"Total groups: {groups_total[0]}")

conn.close()
print("\nDone! Refresh your subscriptions page.")
