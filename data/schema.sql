CREATE TABLE cache (
    origin TEXT NOT NULL,
    url TEXT NOT NULL,
    max_age INT NOT NULL,
    credentials BOOLEAN NOT NULL,
    method TEXT,
    header TEXT,
    created_at INT NOT NULL
);
