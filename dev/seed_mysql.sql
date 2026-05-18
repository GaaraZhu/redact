-- Gate demo seed data (MySQL/MariaDB)
-- Adapted from seed.sql: SERIAL → INT AUTO_INCREMENT

DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  full_name     TEXT,
  email         TEXT,
  phone_number  TEXT,
  ird_number    TEXT,
  country       TEXT,
  created_at    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE transactions (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  user_id      INT,
  amount       NUMERIC(10,2),
  card_number  TEXT,
  merchant     TEXT,
  category     TEXT,
  status       TEXT,
  created_at   TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (id, full_name, email, phone_number, ird_number, country) VALUES
  (1, 'Alice Johnson',  'alice@example.com',   '555-867-5309', '049-091-850', 'NZ'),
  (2, 'Bob Smith',      'bob@example.com',     '555-123-4567', '136-410-132', 'NZ'),
  (3, 'Carol Martinez', 'carol@example.com',   '555-234-5678', '085-766-988', 'AU'),
  (4, 'David Lee',      'david@example.com',   '555-345-6789', '103-254-869', 'AU');

INSERT INTO transactions (id, user_id, amount, card_number, merchant, category, status) VALUES
  (1,  1,  49.99, '4111111111111111', 'Spotify',        'Subscription', 'completed'),
  (2,  1, 120.00, '4111111111111111', 'Amazon',         'Shopping',     'completed'),
  (3,  1,  15.50, '4111111111111111', 'Uber Eats',      'Food',         'completed'),
  (4,  2,  89.00, '5500005555555559', 'Netflix',        'Subscription', 'completed'),
  (5,  2, 340.00, '5500005555555559', 'Apple Store',    'Electronics',  'completed'),
  (6,  2,  22.80, '5500005555555559', 'Uber Eats',      'Food',         'refunded'),
  (7,  3, 220.50, '340000000000009',  'JB Hi-Fi',       'Electronics',  'completed'),
  (8,  3,  60.00, '340000000000009',  'Woolworths',     'Groceries',    'completed'),
  (9,  3,  12.99, '340000000000009',  'Spotify',        'Subscription', 'completed'),
  (10, 4,  45.00, '6011000990139424', 'Countdown',      'Groceries',    'completed'),
  (11, 4, 199.00, '6011000990139424', 'PB Tech',        'Electronics',  'pending'),
  (12, 4,  33.40, '6011000990139424', 'McDonald''s',    'Food',         'completed');
