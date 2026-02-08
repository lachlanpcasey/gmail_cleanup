import sqlite3

conn = sqlite3.connect('gmail_cleanup.db')
cursor = conn.cursor()

print("=== SUBSCRIPTION_GROUPS TABLE SCHEMA ===")
schema = cursor.execute(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='subscription_groups'").fetchone()
print(schema[0] if schema else "Table not found")

print("\n=== Sample rows with their unsubscribed values ===")
rows = cursor.execute(
    "SELECT id, sender_domain, unsubscribed FROM subscription_groups LIMIT 10").fetchall()
for row in rows:
    print(
        f"ID: {row[0]}, Domain: {row[1]}, Unsubscribed: {row[2]} (type: {type(row[2]).__name__})")

conn.close()
