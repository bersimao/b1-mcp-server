#!/usr/bin/env node
// ============================================================================
// Quick connection test — verifies DirectDb can reach the database.
// Run: node --env-file=.env --loader ts-node/esm scripts/test-connection.ts
//   or: npx tsx --env-file=.env scripts/test-connection.ts
//   or after build: node --env-file=.env dist/scripts/test-connection.js
// ============================================================================

async function main() {
  console.log('=== sps-mcp-server Connection Test ===\n');

  // 1. Check env vars
  const dbType = process.env.MCP_DB_TYPE;
  const server = process.env.MCP_DB_SERVER;
  const database = process.env.MCP_DB_NAME;
  const username = process.env.MCP_DB_USR;
  const password = process.env.MCP_DB_PWD;

  console.log(`DB Type:   ${dbType}`);
  console.log(`Server:    ${server}`);
  console.log(`Database:  ${database}`);
  console.log(`User:      ${username}`);
  console.log(`Password:  ${'*'.repeat(password?.length || 0)}\n`);

  if (!dbType || !server || !database || !username || !password) {
    console.error('❌ Missing required env vars. Check your .env file.');
    process.exit(1);
  }

  // 2. Import DirectDb
  console.log('Importing sps-sap-interface...');
  let DirectDb: any;
  try {
    const spsModule = await import('sps-sap-interface');
    DirectDb = spsModule.DirectDb || spsModule.default?.DirectDb;
    if (!DirectDb) throw new Error('DirectDb not found in exports');
    console.log('✅ sps-sap-interface loaded\n');
  } catch (err) {
    console.error(`❌ Failed to import sps-sap-interface: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  // 3. Init connection
  console.log('Connecting to database...');
  const databaseType = dbType.toLowerCase() === 'hana' ? 'HANA' : 'SQL';

  try {
    await DirectDb.init({ server, database, databaseType, username, password });
    console.log('✅ DirectDb.init() succeeded\n');
  } catch (err) {
    console.error(`❌ DirectDb.init() failed: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  // 4. Ping query
  const pingQuery = dbType.toLowerCase() === 'hana'
    ? 'SELECT CURRENT_DATE FROM DUMMY'
    : 'SELECT GETDATE()';

  console.log(`Running ping: ${pingQuery}`);
  const start = Date.now();

  try {
    const result = await DirectDb.executeQuery(pingQuery);
    const elapsed = Date.now() - start;
    console.log(`✅ Ping succeeded in ${elapsed}ms`);
    console.log(`   Result: ${JSON.stringify(result)}\n`);
  } catch (err) {
    const elapsed = Date.now() - start;
    console.error(`❌ Ping failed after ${elapsed}ms: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  // 5. Quick schema test
  const schemaQuery = dbType.toLowerCase() === 'hana'
    ? 'SELECT COUNT(*) AS "TableCount" FROM "SYS"."TABLES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA'
    : `SELECT COUNT(*) AS TableCount FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = '${database}'`;

  console.log(`Counting tables: ${schemaQuery}`);
  try {
    const result = await DirectDb.executeQuery(schemaQuery);
    console.log(`✅ Found ${JSON.stringify(result)} tables in ${database}\n`);
  } catch (err) {
    console.error(`⚠️  Schema query failed (non-fatal): ${err instanceof Error ? err.message : err}\n`);
  }

  console.log('=== Connection test PASSED ===');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
