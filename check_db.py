import sqlite3

conn = sqlite3.connect("reghunt.db")
c = conn.cursor()

# See what key_path and value_name were stored for FreshCriticalTest
c.execute("SELECT key_path, value_name, value_data FROM sysmon_registry_events WHERE value_name LIKE '%FreshCriticalTest%'")
for row in c.fetchall():
    print(f"Stored key_path: {row[0]!r}")
    print(f"Stored value_name: {row[1]!r}")
    print(f"Stored value_data: {row[2]!r}")

# See what reg_path is stored for the entry
c.execute("SELECT reg_path, name FROM registry_entries WHERE name = 'FreshCriticalTest'")
for row in c.fetchall():
    print(f"Entry reg_path: {row[0]!r}")
    print(f"Entry name: {row[1]!r}")

conn.close()