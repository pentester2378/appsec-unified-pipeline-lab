'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

test('Express app exposes route and health endpoint', () => {
  const source = fs.readFileSync(path.join(root, 'src/app.js'), 'utf8');
  assert.match(source, /app\.get\('\/health'/);
  assert.match(source, /app\.get\('\/search\/:category'/);
});

test('Docker compose references app and PostgreSQL', () => {
  const text = fs.readFileSync(path.join(root, 'compose.test.yml'), 'utf8');
  assert.match(text, /postgres:16-alpine/);
  assert.match(text, /ENABLE_CSP/);
});
