-- Skema database Cloudflare D1 untuk Undangan Pernikahan
CREATE TABLE IF NOT EXISTS guests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    status_rsvp TEXT DEFAULT 'pending', -- 'Hadir', 'Tidak Hadir', 'pending'
    wishes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_guests_slug ON guests(slug);

-- Tabel Rate Limiting Server-Side per IP
CREATE TABLE IF NOT EXISTS rsvp_rate_limits (
    ip_hash TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 1,
    first_attempt_at INTEGER NOT NULL,
    last_attempt_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rsvp_rate_limits(last_attempt_at);

