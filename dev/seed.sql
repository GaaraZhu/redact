-- Demo database for redact end-to-end testing.
-- All data is synthetic — emails and card numbers are fake.

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    first_name    TEXT NOT NULL,      -- PII
    last_name     TEXT NOT NULL,      -- PII
    date_of_birth DATE NOT NULL,      -- PII
    plan          TEXT NOT NULL DEFAULT 'free',
    region        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    email         TEXT NOT NULL,      -- PII
    credit_card   TEXT NOT NULL       -- PII
);

-- Credit cards are well-known Luhn-valid test vectors.
INSERT INTO users (first_name, last_name, date_of_birth, plan, region, status, email, credit_card) VALUES
  ('Alice',   'Johnson',   '1990-03-14', 'pro',      'us-west',    'active',   'alice.johnson@example.com',   '4111111111111111'),
  ('Bob',     'Williams',  '1985-07-22', 'free',     'eu-central', 'active',   'bob.williams@example.com',    '4012888888881881'),
  ('Carol',   'Martinez',  '1993-11-05', 'pro',      'us-east',    'active',   'carol.martinez@example.com',  '5500005555555559'),
  ('David',   'Chen',      '1978-01-30', 'free',     'ap-south',   'inactive', 'david.chen@example.com',      '371449635398431'),
  ('Eve',     'Okonkwo',   '2001-09-18', 'enterprise','us-west',   'active',   'eve.okonkwo@example.com',     '6011111111111117');
