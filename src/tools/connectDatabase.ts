// ============================================================================
// Tool: connect_database - switch active database + Service Layer connection
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

// ---------------------------------------------------------------------------
// Failed connection attempt tracker
// SAP B1 locks user accounts after repeated failed login attempts.
// We track failures per profile+side to warn before a lockout occurs.
// ---------------------------------------------------------------------------

const SAP_LOCKOUT_WARNING_THRESHOLD = 3;

interface FailedAttempts {
  db: number;
  sl: number;
}

const failedAttemptsMap = new Map<string, FailedAttempts>();

function getFailedAttempts(profileId: string): FailedAttempts {
  if (!failedAttemptsMap.has(profileId)) {
    failedAttemptsMap.set(profileId, { db: 0, sl: 0 });
  }
  return failedAttemptsMap.get(profileId)!;
}

function recordFailure(profileId: string, side: 'db' | 'sl'): number {
  const attempts = getFailedAttempts(profileId);
  attempts[side]++;
  return attempts[side];
}

function resetFailures(profileId: string, side: 'db' | 'sl'): void {
  const attempts = getFailedAttempts(profileId);
  attempts[side] = 0;
}

function formatLockoutWarning(profileId: string, side: string, count: number): string {
  if (count >= SAP_LOCKOUT_WARNING_THRESHOLD) {
    return `\nWARNING: ${count} consecutive failed ${side} login attempts for "${profileId}". SAP B1 may lock this user account after repeated failures. Please verify the credentials before retrying.`;
  }
  return '';
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
    ? profiles.map(p => `  - "${p.id}" -> ${p.dbName} (${p.dbType}) [${formatCapabilities(p)}]`).join('\n')
    : '  (no profiles loaded)';

  server.tool(
    'connect_database',
    `Switch the active database and Service Layer connection to a different SAP Business One environment.
Searches connection profiles by ID or database name (case-insensitive). Partial matches are only accepted when they resolve to a single profile.

Each profile can include DirectDb (DB) credentials, Service Layer (SL) credentials, or both.
When switching environments, both previous connections are always disconnected first to prevent cross-environment operations.
If only one side connects successfully, it remains active - retry the failed side after fixing credentials.
Tracks failed login attempts per profile and warns about SAP B1 account lockout risk.

Available profiles:
${profileList}

Use "list" as the query to reload and list all available profiles.`,
    {
      query: z.string().describe(
        'The database identifier to connect to. Can be the profile ID or database name. Use "list" to see all available profiles.'
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
          const active = currentDb && p.dbName === currentDb ? ' <- active' : '';
          return `  ${p.id} -> ${p.dbName} (${p.dbType}) [${formatCapabilities(p)}]${active}`;
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
        const partialMatches = connectionManager.findPartialMatches(query);
        const allProfiles = connectionManager.listAll();

        if (partialMatches.length > 1) {
          return {
            content: [{
              type: 'text' as const,
              text:
                `Ambiguous profile query "${query}". ${partialMatches.length} profiles match:\n` +
                partialMatches.map(p => `  - ${p.id} -> ${p.dbName}`).join('\n') +
                '\n\nPlease retry using the exact profile ID.',
            }],
            isError: true,
          };
        }

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

      // --- Determine what needs (re)connecting ---
      // When switching to a different environment, BOTH previous connections
      // must be ended first so we never have DB on one env and SL on another.
      // When retrying a failed side on the SAME profile, only connect that side.
      const hasDb = hasDbCredentials(profile);
      const hasSl = hasSlCredentials(profile);

      const dbAlreadyOnTarget = adapter.isConnected() && adapter.getDbName() === profile.dbName;
      const slAlreadyOnTarget = slAdapter.isConnected() && slAdapter.getDbName() === profile.dbName;

      // Both already connected to the target - nothing to do
      if (dbAlreadyOnTarget && slAlreadyOnTarget) {
        return {
          content: [{ type: 'text' as const, text: `Already connected to "${profile.id}" (${profile.dbName}). No changes made.` }],
        };
      }

      // Switching to a different environment - disconnect both first
      const isSameTarget =
        (!adapter.isConnected() || adapter.getDbName() === profile.dbName) &&
        (!slAdapter.isConnected() || slAdapter.getDbName() === profile.dbName);

      if (!isSameTarget) {
        const previousDbName = adapter.getDbName() || slAdapter.getDbName();
        adapter.disconnect();
        slAdapter.disconnect();
        console.error(`[connect] Switched away from "${previousDbName}" - both connections ended.`);
      }

      // --- Connect DirectDb (skip if already on target) ---
      let dbConnected = dbAlreadyOnTarget;
      let dbError: string | undefined;
      let dbPingMs: number | undefined;

      if (hasDb && !dbAlreadyOnTarget) {
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
          if (!check.connected) {
            dbError = check.error;
            adapter.disconnect();
          }
        } catch (err) {
          dbError = err instanceof Error ? err.message : String(err);
          adapter.disconnect();
        }

        if (dbConnected) {
          resetFailures(profile.id, 'db');
        } else {
          recordFailure(profile.id, 'db');
        }
      }

      // --- Connect Service Layer (skip if already on target) ---
      let slConnected = slAlreadyOnTarget;
      let slError: string | undefined;
      let slPingMs: number | undefined;

      if (hasSl && !slAlreadyOnTarget) {
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
          if (!check.connected) {
            slError = check.error;
            slAdapter.disconnect();
          }
        } catch (err) {
          slError = err instanceof Error ? err.message : String(err);
          slAdapter.disconnect();
        }

        if (slConnected) {
          resetFailures(profile.id, 'sl');
        } else {
          recordFailure(profile.id, 'sl');
        }
      }

      // --- Build response ---
      const lines: string[] = [];
      lines.push(`Profile: "${profile.id}" (${profile.dbName})`);
      lines.push('');

      if (hasDb) {
        if (dbConnected) {
          lines.push(`DirectDb: Connected (${profile.dbType})${dbPingMs != null ? ` - ${dbPingMs}ms` : ''}`);
        } else {
          lines.push(`DirectDb: FAILED - ${dbError}`);
        }
      } else {
        lines.push('DirectDb: Not configured (no dbServer/dbUser in profile)');
      }

      if (hasSl) {
        if (slConnected) {
          lines.push(`ServiceLayer: Connected via ${profile.slUrl}${slPingMs != null ? ` - ${slPingMs}ms` : ''}`);
        } else {
          lines.push(`ServiceLayer: FAILED - ${slError}`);
        }
      } else {
        lines.push('ServiceLayer: Not configured (no slUrl/slUser in profile)');
      }

      // Append lockout warnings if thresholds are reached
      const attempts = getFailedAttempts(profile.id);
      const dbLockoutWarn = formatLockoutWarning(profile.id, 'DirectDb', attempts.db);
      const slLockoutWarn = formatLockoutWarning(profile.id, 'ServiceLayer', attempts.sl);
      if (dbLockoutWarn) lines.push(dbLockoutWarn);
      if (slLockoutWarn) lines.push(slLockoutWarn);

      // Audit
      const auditEntry = logger.createEntry({
        tool: 'connect_database',
        database: profile.dbName,
        dbType: profile.dbType,
        operation: OperationType.OTHER,
        tables: [],
        query: `CONNECT TO ${profile.dbName}`,
        decision: dbConnected || slConnected ? 'ALLOW' : 'DENY',
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
