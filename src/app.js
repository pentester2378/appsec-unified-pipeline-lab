'use strict';

const express = require('express');
const { Pool } = require('pg');
const { rateLimit } = require('express-rate-limit');

const app = express();
app.disable('x-powered-by');

// The DAST scenario switches this *runtime* defence in compose.test.yml.
// A deliberately disabled CSP is only appropriate in the isolated PoC.
if (process.env.ENABLE_CSP !== 'false') {
  app.use((req, res, next) => {
    res.set('Content-Security-Policy', "default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    next();
  });
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
});

app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AppSec Unified PoC</title></head>
<body><main><h1>AppSec Unified PoC</h1>
<p>Web app used for SAST then DAST on the same build.</p>
<a href="/search/fruit">Example products</a></main></body></html>`);
});

app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

app.get('/search/:category', searchLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT item, price FROM product WHERE item_category = $1',
      [req.params.category]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Product search failed', error.message);
    res.status(500).json({ error: 'Database error' });
  }
});

module.exports = { app, pool };
