-- Demo database for redact end-to-end testing.
-- All data is synthetic — names, emails, SSNs, cards, and addresses are fake.

CREATE TABLE users (
    id          SERIAL PRIMARY KEY,
    first_name  TEXT NOT NULL,
    last_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    phone       TEXT,
    ssn         TEXT,
    dob         DATE,
    address     TEXT,
    credit_card TEXT,
    plan        TEXT NOT NULL DEFAULT 'free'
);

CREATE TABLE orders (
    id         SERIAL PRIMARY KEY,
    user_id    INT REFERENCES users(id),
    product    TEXT NOT NULL,
    amount     NUMERIC(10, 2) NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- SSNs use the 000-xx-xxxx prefix which is structurally valid but never issued.
-- Credit cards are well-known Luhn-valid test vectors (Stripe / PaymentsBridge test suite).
INSERT INTO users (first_name, last_name, email, phone, ssn, dob, address, credit_card, plan) VALUES
  ('Alice',   'Johnson',   'alice.johnson@example.com',   '555-234-5678', '000-12-3456', '1985-03-15', '42 Maple St, Springfield, IL 62701',   '4111111111111111', 'pro'),
  ('Bob',     'Williams',  'bob.williams@example.com',    '555-345-6789', '000-23-4567', '1990-07-22', '17 Oak Ave, Portland, OR 97201',        '4012888888881881', 'free'),
  ('Carol',   'Davis',     'carol.davis@example.com',     '555-456-7890', '000-34-5678', '1978-11-08', '88 Pine Rd, Austin, TX 78701',          '5500005555555559', 'pro'),
  ('David',   'Miller',    'david.miller@example.com',    '555-567-8901', '000-45-6789', '1995-02-28', '3 Elm Blvd, Denver, CO 80201',          '371449635398431',  'free'),
  ('Emma',    'Wilson',    'emma.wilson@example.com',     '555-678-9012', '000-56-7890', '1988-09-14', '55 Cedar Ln, Seattle, WA 98101',        '6011111111111117', 'pro'),
  ('Frank',   'Taylor',    'frank.taylor@example.com',    '555-789-0123', '000-67-8901', '1972-06-30', '21 Birch Way, Boston, MA 02101',        '3566002020360505', 'free'),
  ('Grace',   'Anderson',  'grace.anderson@example.com',  '555-890-1234', '000-78-9012', '1993-12-05', '99 Walnut St, Chicago, IL 60601',       '4111111111111111', 'pro'),
  ('Henry',   'Thomas',    'henry.thomas@example.com',    '555-901-2345', '000-89-0123', '1982-04-19', '7 Spruce Ct, Miami, FL 33101',          '4012888888881881', 'free');

INSERT INTO orders (user_id, product, amount, status) VALUES
  (1, 'Pro Plan - Annual',    299.00, 'completed'),
  (1, 'Add-on: Extra Seats',   49.00, 'completed'),
  (2, 'Free Plan',               0.00, 'active'),
  (3, 'Pro Plan - Monthly',    29.00, 'completed'),
  (3, 'Support Package',        99.00, 'pending'),
  (4, 'Free Plan',               0.00, 'active'),
  (5, 'Pro Plan - Annual',    299.00, 'completed'),
  (6, 'Free Plan',               0.00, 'active'),
  (7, 'Pro Plan - Monthly',    29.00, 'completed'),
  (8, 'Free Plan',               0.00, 'active');
