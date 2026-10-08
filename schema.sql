CREATE TABLE IF NOT EXISTS iocs (
  id         SERIAL PRIMARY KEY,
  value      TEXT NOT NULL,
  ioc_type   TEXT NOT NULL CHECK (ioc_type IN ('url','ip','domain','md5','sha1','sha256')),
  sources    TEXT[] NOT NULL,
  family     TEXT,
  status     TEXT,
  tags       TEXT[],
  threat     TEXT,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (value, ioc_type)
);