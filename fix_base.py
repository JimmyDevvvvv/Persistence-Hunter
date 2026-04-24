methods = '''
    def create_baseline(self, name="default", note=""):
        from datetime import datetime as _dt
        now = _dt.utcnow().isoformat()
        cur = self.conn.execute(
            "INSERT INTO baselines (name, created_at, note) VALUES (?, ?, ?)",
            (name, now, note)
        )
        bl_id = cur.lastrowid
        for entry_type, table in [("registry","registry_entries"),("task","task_entries"),("service","service_entries")]:
            rows = self.conn.execute(f"SELECT hash_id FROM {table}").fetchall()
            for row in rows:
                try:
                    self.conn.execute("INSERT OR IGNORE INTO baseline_entries (baseline_id, entry_type, hash_id) VALUES (?, ?, ?)", (bl_id, entry_type, row["hash_id"]))
                except Exception:
                    pass
        self.conn.commit()
        return bl_id

    def get_active_baseline(self):
        row = self.conn.execute("SELECT * FROM baselines ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def list_baselines(self):
        rows = self.conn.execute("SELECT b.id, b.name, b.created_at, b.note, COUNT(be.id) as entry_count FROM baselines b LEFT JOIN baseline_entries be ON be.baseline_id = b.id GROUP BY b.id ORDER BY b.id DESC").fetchall()
        return [dict(r) for r in rows]

    def mark_safe(self, entry_type, hash_id):
        bl = self.get_active_baseline()
        if not bl:
            self.create_baseline(note="auto-created by mark-safe")
            bl = self.get_active_baseline()
        try:
            self.conn.execute("INSERT INTO baseline_entries (baseline_id, entry_type, hash_id, safe) VALUES (?, ?, ?, 1) ON CONFLICT(baseline_id, entry_type, hash_id) DO UPDATE SET safe = 1", (bl["id"], entry_type, hash_id))
            self.conn.commit()
            return True
        except Exception:
            return False

    def is_baselined(self, entry_type, hash_id, baseline_id=None):
        if baseline_id is None:
            bl = self.get_active_baseline()
            if not bl:
                return False
            baseline_id = bl["id"]
        row = self.conn.execute("SELECT 1 FROM baseline_entries WHERE baseline_id = ? AND entry_type = ? AND hash_id = ?", (baseline_id, entry_type, hash_id)).fetchone()
        return row is not None

    def get_new_entries(self, entry_type, table, baseline_id=None):
        if baseline_id is None:
            bl = self.get_active_baseline()
            baseline_id = bl["id"] if bl else None
        if baseline_id is None:
            rows = self.conn.execute(f"SELECT * FROM {table}").fetchall()
            return [dict(r) for r in rows]
        rows = self.conn.execute(f"SELECT t.* FROM {table} t WHERE NOT EXISTS (SELECT 1 FROM baseline_entries be WHERE be.baseline_id = ? AND be.entry_type = ? AND be.hash_id = t.hash_id)", (baseline_id, entry_type)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
'''

with open('collector/base_collector.py', 'r') as f:
    content = f.read()

if 'def create_baseline' in content:
    print("Already patched.")
else:
    content = content.replace('    def close(self):', methods)
    with open('collector/base_collector.py', 'w') as f:
        f.write(content)
    print("Patched successfully.")