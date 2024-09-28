DROP TABLE IF EXISTS requests CASCADE;

CREATE TABLE IF NOT EXISTS requests (
    id SERIAL PRIMARY KEY,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    get_params JSONB,
    headers JSONB,
    cookies JSONB,
    post_params JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);