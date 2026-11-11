CREATE TABLE IF NOT EXISTS product (
  id SERIAL PRIMARY KEY,
  item TEXT NOT NULL,
  price NUMERIC(8,2) NOT NULL,
  item_category TEXT NOT NULL
);

INSERT INTO product (item, price, item_category) VALUES
  ('apple', 1.20, 'fruit'),
  ('pear', 1.50, 'fruit'),
  ('carrot', 0.80, 'vegetable');
