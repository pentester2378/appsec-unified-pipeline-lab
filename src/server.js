'use strict';

const { app, pool } = require('./app');
const port = Number.parseInt(process.env.PORT || '3000', 10);

async function start() {
  // Do not publish a listener until the database is reachable.
  await pool.query('SELECT 1');
  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`AppSec unified demo listening on port ${port}`);
  });
  const shutdown = async () => {
    server.close(async () => {
      await pool.end();
      process.exit(0);
    });
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

start().catch((error) => {
  console.error('Startup failed:', error.message);
  process.exit(1);
});
