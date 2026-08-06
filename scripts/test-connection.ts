#!/usr/bin/env node
// ============================================================================
// Quick connection test — verifies DirectDb can reach a database defined in
// ~/.claude/connections.json.
//
// Run: npx tsx scripts/test-connection.ts <profile-id>
//   or after build: node dist/scripts/test-connection.js <profile-id>
// ============================================================================

import { ConnectionManager } from '../src/config/connectionManager.js';
import { DirectDb } from '../src/db/directDb.js';

async function main() {
  console.log('=== sps-mcp-server Connection Test ===\n');

  // 1. Resolve profile from CLI arg
  const profileId = process.argv[2];
  if (!profileId) {
    console.error('❌ Missing profile id.');
    console.error('Usage: npx tsx scripts/test-connection.ts <profile-id>');
    process.exit(1);
  }

  const manager = new ConnectionManager();
  manager.load();
  const profile = manager.find(profileId);

  if (!profile) {
    const available = manager.listAll().map(p => p.id).join(', ') || '(none)';
    console.error(`❌ No profile matching "${profileId}" in ${manager.getFilePath()}`);
    console.error(`   Available: ${available}`);
    process.exit(1);
  }

  const { dbType, dbServer, dbName, dbUser, dbPassword } = profile;

  console.log(`Profile:   ${profile.id}`);
  console.log(`DB Type:   ${dbType}`);
  console.log(`Server:    ${dbServer}`);
  console.log(`Database:  ${dbName}`);
  console.log(`User:      ${dbUser}`);
  console.log(`Password:  ${'*'.repeat(dbPassword.length)}\n`);

  if (!dbServer || !dbUser || !dbPassword) {
    console.error('❌ Profile is missing dbServer / dbUser / dbPassword.');
    process.exit(1);
  }

  // 2. Init connection
  const directDb = new DirectDb();
  console.log('Connecting to database...');
  const databaseType = dbType === 'hana' ? 'HANA' : 'SQL';

  try {
    try {
      await directDb.init({ server: dbServer, database: dbName, databaseType, username: dbUser, password: dbPassword });
      console.log('✅ DirectDb.init() succeeded\n');
    } catch (err) {
      console.error(`❌ DirectDb.init() failed: ${err instanceof Error ? err.message : err}`);
      process.exitCode = 1;
      return;
    }

    // 3. Ping query
    const pingQuery = dbType === 'hana'
      ? 'SELECT CURRENT_DATE FROM DUMMY'
      : 'SELECT GETDATE()';

    console.log(`Running ping: ${pingQuery}`);
    const start = Date.now();

    try {
      const result = await directDb.executeQuery(pingQuery);
      const elapsed = Date.now() - start;
      console.log(`✅ Ping succeeded in ${elapsed}ms`);
      console.log(`   Result: ${JSON.stringify(result)}\n`);
    } catch (err) {
      const elapsed = Date.now() - start;
      console.error(`❌ Ping failed after ${elapsed}ms: ${err instanceof Error ? err.message : err}`);
      process.exitCode = 1;
      return;
    }

    // 4. Quick schema test
    const schemaQuery = dbType === 'hana'
      ? 'SELECT COUNT(*) AS "TableCount" FROM "SYS"."TABLES" WHERE "SCHEMA_NAME" = CURRENT_SCHEMA'
      : `SELECT COUNT(*) AS TableCount FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = '${dbName}'`;

    console.log(`Counting tables: ${schemaQuery}`);
    try {
      const result = await directDb.executeQuery(schemaQuery);
      console.log(`✅ Found ${JSON.stringify(result)} tables in ${dbName}\n`);
    } catch (err) {
      console.error(`⚠️  Schema query failed (non-fatal): ${err instanceof Error ? err.message : err}\n`);
    }

    console.log('=== Connection test PASSED ===');
  } finally {
    await directDb.close();
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
