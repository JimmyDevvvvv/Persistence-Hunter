import sqlite3
conn = sqlite3.connect('reghunt.db')
conn.executescript("""
    CREATE TABLE IF NOT EXISTS baselines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL DEFAULT 'default',
        created_at TEXT NOT NULL,
        note TEXT
    );
    CREATE TABLE IF NOT EXISTS baseline_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        baseline_id INTEGER NOT NULL,
        entry_type TEXT NOT NULL,
        hash_id TEXT NOT NULL,
        safe INTEGER DEFAULT 0,
        UNIQUE(baseline_id, entry_type, hash_id)
    );
    CREATE INDEX IF NOT EXISTS idx_bl_entries ON baseline_entries(baseline_id, entry_type, hash_id);
""")
conn.commit()
conn.close()
print("DB tables created.")