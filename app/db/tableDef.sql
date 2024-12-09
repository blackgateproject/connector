
-- ...existing code...

CREATE TABLE IF NOT EXISTS user_keys (
    user_id UUID PRIMARY KEY,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    two_factor_auth BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ...existing code...