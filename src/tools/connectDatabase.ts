// ============================================================================
// Tool: connect_database — switch active database + Service Layer connection
// ============================================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { DbAdapter } from '../db/adapter.js';
import { ServiceLayerAdapter } from '../sl/serviceLayerAdapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { ConnectionManager, ConnectionProfile } from '../config/connectionManager.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';

/** Check if a profile has DirectDb credentials configured. */
function hasDbCredentials(p: ConnectionProfile): boolean {
  return !!(p.dbServer && p.dbUser);
}

/** Check if a profile has Service Layer credentials configured. */
function hasSlCredentials(p: ConnectionProfile): boolean {
  return !!(p.slUrl && p.slUser);
}

/** Format connection capabilities for display. */
function formatCapabilities(p: ConnectionProfile): string {
  const caps: string[] = [];
  if (hasDbCredentials(p)) caps.push('DB');
  if (hasSlCredentials(p)) caps.push('SL');
  return caps.join('+') || 'none';
}

export function registerConnectDatabaseTool(
  server: McpServer,
  adapter: DbAdapter,
  slAdapter: ServiceLayerAdapter,
  logger: AuditLogger,
  config: Config,
  connectionManager: ConnectionManager,
  rateLimiter: RateLimiter,
): void {
  const profiles = connectionManager.listAll();
  const profileList = profiles.length > 0
    ? profiles.map(p => `  - "${p.id}" → ${p.dbName} (${p.dbType}) [${formatCapabilities(p)}]`).join('\n')
    : '  (no profiles loaded)';

  server.tool(
    'connect_database',
    `Switch the active database and Service Layer connection to a different SAP Business One environment.
Searches connection profiles by ID, database name, or display name (case-insensitive, partial match supported).

Each profile can include DirectDb (DB) credentials, Service Layer (SL) credentials, or both.
Both connections are established in one step. If one fails, the other still connects.

Available profiles:
${profileList}

Use "list" as the query to reload and list all available profiles.`,
    {
      query: z.string().describe(
        'The database identifier to connect to. Can be the profile ID, database name, or display name. Use "list" to see all available profiles.'
      ),
    },
    async ({ query }) => {
      const rateCheck = rateLimiter.check('connect_database');
      if (!rateCheck.allowed) {
        return {
          content: [{ type: 'text' as const, text: `Rate limit exceeded for connect_database. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }],
          isError: true,
        };
      }

      // Special "list" command: reload profiles and show all
      if (query.toLowerCase() === 'list') {
        connectionManager.reload();
        const allProfiles = connectionManager.listAll();

        if (allProfiles.length === 0) {
          return {
            content: [{
              type: 'text' as const,
              text: `No connection profiles found.\nFile: ${connectionManager.getFilePath()}\n\nCreate the file with an array of connection objects.`,
            }],
          };
        }

        const currentDb = adapter.isConnected() ? adapter.getDbName() : null;
        const lines = allProfiles.map(p => {
          const active = currentDb && p.dbName === currentDb ? ' ← active' : '';
          return `  ${p.id} → ${p.dbName} (${p.dbType}) [${formatCapabilities(p)}]${active}`;
        });

        return {
          content: [{
            type: 'text' as const,
            text: `Available connection profiles (${allProfiles.length}):\n${lines.join('\n')}`,
          }],
        };
      }

      // Find the profile
      const profile = connectionManager.find(query);
      if (!profile) {
        const allProfiles = connectionManager.listAll();
        const hint = allProfiles.length > 0
          ? `\nAvailable: ${allProfiles.map(p => p.id).join(', ')}`
          : `\nNo profiles loaded. Check ${connectionManager.getFilePath()}`;

        return {
          content: [{
            type: 'text' as const,
            text: `No connection profile matching "${query}" found.${hint}`,
          }],
          isError: true,
        };
      }

      // --- Connect DirectDb ---
      let dbConnected = false;
      let dbError: string | undefined;
      let dbPingMs: number | undefined;

      if (hasDbCredentials(profile)) {
        // Skip if already connected to this database via DirectDb
        if (adapter.isConnected() && adapter.getDbName() === profile.dbName) {
          dbConnected = true;
        } else {
          try {
            await adapter.init({
              server: profile.dbServer,
              database: profile.dbName,
              dbType: profile.dbType,
              username: profile.dbUser,
              password: profile.dbPassword,
            });
            const check = await adapter.checkConnection();
            dbConnected = check.connected;
            dbPingMs = check.durationMs;
            if (!check.connected) dbError = check.error;
          } catch (err) {
            dbError = err instanceof Error ? err.message : String(err);
          }
        }
      }

      // --- Connect Service Layer ---
      let slConnected = false;
      let slError: string | undefined;
      let slPingMs: number | undefined;

      if (hasSlCredentials(profile)) {
        // Skip if already connected to this database via SL
        if (slAdapter.isConnected() && slAdapter.getDbName() === profile.dbName) {
          slConnected = true;
        } else {
          try {
            await slAdapter.init({
              database: profile.dbName,
              username: profile.slUser!,
              password: profile.slPassword || '',
              url: profile.slUrl!,
            });
            const check = await slAdapter.checkConnection();
            slConnected = check.connected;
            slPingMs = check.durationMs;
            if (!check.connected) slError = check.error;
          } catch (err) {
            slError = err instanceof Error ? err.message : String(err);
          }
        }
      }

      // --- Build response ---
      const lines: string[] = [];
      lines.push(`Profile: "${profile.name}" (${profile.dbName})`);
      lines.push('');

      if (hasDbCredentials(profile)) {
        if (dbConnected) {
          lines.push(`DirectDb: Connected (${profile.dbType})${dbPingMs != null ? ` — ${dbPingMs}ms` : ''}`);
        } else {
          lines.push(`DirectDb: FAILED — ${dbError}`);
        }
      } else {
        lines.push('DirectDb: Not configured (no dbServer/dbUser in profile)');
      }

      if (hasSlCredentials(profile)) {
        if (slConnected) {
          lines.push(`ServiceLayer: Connected via ${profile.slUrl}${slPingMs != null ? ` — ${slPingMs}ms` : ''}`);
        } else {
          lines.push(`ServiceLayer: FAILED — ${slError}`);
        }
      } else {
        lines.push('ServiceLayer: Not configured (no slUrl/slUser in profile)');
      }

      // Audit
      const auditEntry = logger.createEntry({
        tool: 'connect_database',
        database: profile.dbName,
        dbType: profile.dbType,
        operation: OperationType.OTHER,
        tables: [],
        query: `CONNECT TO ${profile.dbName}`,
        decision: 'ALLOW',
        reason: `DB: ${dbConnected ? 'OK' : dbError || 'not configured'}, SL: ${slConnected ? 'OK' : slError || 'not configured'}`,
        rule: 'connectDatabase',
      });
      logger.log(auditEntry);

      const anyConnected = dbConnected || slConnected;
      return {
        content: [{ type: 'text' as const, text: lines.join('\n') }],
        isError: !anyConnected,
      };
    },
  );
}
