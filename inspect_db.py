import sqlite3
conn = sqlite3.connect('flood_reports.db')
conn.row_factory = sqlite3.Row
print("=== TABLES ===")
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
for t in tables:
    print(t[0])
print("\n=== REPORTS SCHEMA ===")
for c in conn.execute("PRAGMA table_info(reports)").fetchall():
    print(dict(c))
print("\n=== REPORTS COUNT ===")
print(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0])
print("\n=== SAMPLE REPORTS ===")
for r in conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 5").fetchall():
    print(dict(r))
conn.close()
