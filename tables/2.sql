DROP TABLE IF EXISTS responses CASCADE;

CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    request_id INT REFERENCES requests(id),
    status_code VARCHAR(10),
    status_message TEXT,
    headers JSONB,
    body TEXT,
    response_time TIMESTAMP DEFAULT NOW()
);