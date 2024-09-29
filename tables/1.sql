DROP TABLE IF EXISTS requests CASCADE;

CREATE TABLE IF NOT EXISTS requests (
    id SERIAL PRIMARY KEY,
    method VARCHAR(10),
    path TEXT,
    get_params JSONB,
    headers JSONB,
    cookies JSONB,
    post_params JSONB,
    request_time TIMESTAMP DEFAULT NOW()
);