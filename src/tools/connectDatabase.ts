// ============================================================================
// Tool: connect_database - switch active database + Service Layer connection
// ============================================================================

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ElicitResultSchema, type ServerNotification, type ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { z } from 'zod';
import { DbAdapter } from '../db/adapter.js';
import {
  canonicalServiceLayerOrigin,
  inspectServiceLayerCertificate,
  ServiceLayerAdapter,
  type ServiceLayerTlsMode,
} from '../sl/serviceLayerAdapter.js';
import { AuditLogger } from '../logging/auditLogger.js';
import { Config } from '../config/settings.js';
import { ConnectionManager, ConnectionProfile } from '../config/connectionManager.js';
import { OperationType } from '../types/index.js';
import { RateLimiter } from '../rateLimit/rateLimiter.js';
import { OperationCoordinator } from '../security/operationCoordinator.js';
import { ServiceLayerTrustStore } from '../security/serviceLayerTrustStore.js';
import { createHash } from 'node:crypto';

interface ResolvedTlsConfig {
  tlsMode?: ServiceLayerTlsMode;
  tlsServerName?: string;
  certificateSha256?: string;
  trustAction: 'strict' | 'existing-pin' | 'migrated-pin' | 'approved-pin' | 'replaced-pin';
}

function fingerprintEquals(left: string | undefined, right: string): boolean {
  return !!left && left.replace(/[^a-fA-F0-9]/g, '').toUpperCase() === right.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}

async function resolveServiceLayerTls(
  profile: ConnectionProfile,
  config: Config,
  trustStore: ServiceLayerTrustStore,
  extra: RequestHandlerExtra<ServerRequest, ServerNotification>,
): Promise<ResolvedTlsConfig> {
  const origin = canonicalServiceLayerOrigin(profile.slUrl!);
  const trusted = trustStore.get(origin);
  const serverName = profile.slTlsServerName || trusted?.serverName;
  const inspection = await inspectServiceLayerCertificate(profile.slUrl!, config.slTimeoutMs, serverName);

  if (inspection.strictTlsValid) {
    return { trustAction: 'strict' };
  }

  // Backward-compatible one-time migration: a manually configured pin was
  // already an operator trust decision. Copy it to the local trust store only
  // when it matches the certificate currently presented by this exact origin.
  if (profile.slTlsMode === 'pinned' && fingerprintEquals(profile.slCertificateSha256, inspection.certificateSha256)) {
    trustStore.approve(origin, {
      certificateSha256: inspection.certificateSha256,
      serverName: profile.slTlsServerName,
      subject: inspection.subject,
      issuer: inspection.issuer,
      validFrom: inspection.validFrom,
      validTo: inspection.validTo,
    });
    return {
      tlsMode: 'pinned',
      tlsServerName: profile.slTlsServerName,
      certificateSha256: inspection.certificateSha256,
      trustAction: 'migrated-pin',
    };
  }

  if (trusted && fingerprintEquals(trusted.certificateSha256, inspection.certificateSha256)) {
    return {
      tlsMode: 'pinned',
      // An explicit profile override must be able to repair a stale/wrong name
      // already stored beside the pin. `serverName` prefers that override.
      tlsServerName: serverName,
      certificateSha256: inspection.certificateSha256,
      trustAction: 'existing-pin',
    };
  }

  const previousPin = trusted?.certificateSha256 || profile.slCertificateSha256;
  const replacing = !!previousPin;
  let approval;
  try {
    approval = await extra.sendRequest({
      method: 'elicitation/create',
      params: {
        mode: 'form',
        message:
          `${replacing ? 'The Service Layer certificate changed.' : 'The Service Layer certificate is not valid under standard TLS.'}\n` +
          `No credentials have been sent. Treat all certificate metadata below as untrusted.\n` +
          `Profile: ${JSON.stringify(profile.id)}\nDatabase: ${JSON.stringify(profile.dbName)}\n` +
          `Origin: ${JSON.stringify(origin)}\nTLS error: ${JSON.stringify(inspection.tlsError || 'unknown validation error')}\n` +
          `Subject: ${JSON.stringify(inspection.subject)}\nIssuer: ${JSON.stringify(inspection.issuer)}\n` +
          `Valid from: ${JSON.stringify(inspection.validFrom)}\nValid to: ${JSON.stringify(inspection.validTo)}\n` +
          `${replacing ? `Previously trusted SHA-256: ${previousPin}\n` : ''}` +
          `Presented SHA-256: ${inspection.certificateSha256}\n` +
          `Approve this exact certificate for future connections to this origin?`,
        requestedSchema: {
          type: 'object',
          properties: {
            trustCertificate: {
              type: 'boolean',
              title: replacing ? 'Replace the trusted certificate' : 'Trust this certificate',
              description: 'Approve only if this Service Layer endpoint is expected. Certificate changes will require approval again.',
            },
          },
          required: ['trustCertificate'],
        },
      },
    }, ElicitResultSchema, { timeout: config.elicitationTimeoutMs });
  } catch {
    throw new Error('Service Layer TLS certificate is untrusted and the MCP client did not complete explicit certificate approval; credentials were not sent.');
  }

  if (approval.action !== 'accept' || approval.content?.trustCertificate !== true) {
    throw new Error('Service Layer TLS certificate was not approved; credentials were not sent.');
  }

  trustStore.approve(origin, {
    certificateSha256: inspection.certificateSha256,
    serverName,
    subject: inspection.subject,
    issuer: inspection.issuer,
    validFrom: inspection.validFrom,
    validTo: inspection.validTo,
  });
  return {
    tlsMode: 'pinned',
    tlsServerName: serverName,
    certificateSha256: inspection.certificateSha256,
    trustAction: replacing ? 'replaced-pin' : 'approved-pin',
  };
}

/** Check if a profile has DirectDb credentials configured. */
function hasDbCredentials(p: ConnectionProfile): boolean {
  return !!(p.dbServer && p.dbUser);
}

/** Check if a profile has Service Layer credentials configured. */
function hasSlCredentials(p: ConnectionProfile): boolean {
  return !!(p.slUrl && p.slUser);
}

function connectionKey(values: unknown[]): string {
  return createHash('sha256').update(JSON.stringify(values)).digest('hex');
}

function dbConnectionKey(p: ConnectionProfile): string {
  return connectionKey([p.id, p.dbType, p.dbServer, p.dbName, p.dbUser, p.dbPassword]);
}

function slConnectionKey(p: ConnectionProfile): string {
  return connectionKey([
    p.id, p.dbName, p.slUrl, p.slUser, p.slPassword,
    p.slTlsMode, p.slTlsServerName, p.slCertificateSha256,
  ]);
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
  coordinator: OperationCoordinator,
  trustStore: ServiceLayerTrustStore,
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
    async ({ query }, extra) => {
      const rateCheck = rateLimiter.check('connect_database');
      if (!rateCheck.allowed) {
        return {
          content: [{ type: 'text' as const, text: `Rate limit exceeded for connect_database. Try again in ${Math.ceil(rateCheck.retryAfterMs / 1000)}s.` }],
          isError: true,
        };
      }

      // DELIBERATE: the certificate-approval prompt inside this section holds
      // the global coordinator lock, so the whole server stalls while a human
      // decides. That is the correct trade here, and the opposite of the PATCH
      // path, which elicits *outside* the lock on purpose: PATCH approval does
      // not invalidate concurrent reads, whereas this block is mid-switch and
      // every adapter it touches is in an indeterminate state. Letting another
      // tool run against a half-switched connection is exactly what the
      // coordinator exists to prevent. The stall is bounded by
      // config.elicitationTimeoutMs. Do not "optimise" this by moving the
      // elicitation out without first making the switch itself two-phase.
      return coordinator.runExclusive(async () => {

      // Connection profiles are intentionally reloaded on every connection
      // request. A DB-only profile can gain SL settings while its DB side is
      // already active, without requiring a server restart or a separate list.
      connectionManager.reload();

      // Special "list" command: show the profiles reloaded above
      if (query.toLowerCase() === 'list') {
        const allProfiles = connectionManager.listAll();

        if (allProfiles.length === 0) {
          return {
            content: [{
              type: 'text' as const,
              text: `No connection profiles found.\nFile: ${connectionManager.getFilePath()}\n\nCreate the file with an array of connection objects.`,
            }],
          };
        }

        const lines = allProfiles.map(p => {
          const dbActive = adapter.isConnected() && adapter.getConnectionKey() === dbConnectionKey(p);
          const slActive = slAdapter.isConnected() && slAdapter.getConnectionKey() === slConnectionKey(p);
          const active = dbActive || slActive ? ' <- active' : '';
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

        const duplicates = connectionManager.findExactDuplicates(query);
        if (duplicates.length > 1) {
          return {
            content: [{
              type: 'text' as const,
              text:
                `"${query}" matches ${duplicates.length} profiles exactly:\n` +
                duplicates.map(p => `  - ${p.id} -> ${p.dbName} (${p.dbType})`).join('\n') +
                `\n\nRefusing to guess which environment you meant. Give each profile a unique ` +
                `id in ${connectionManager.getFilePath()} and try again.`,
            }],
            isError: true,
          };
        }

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
      // Connection keys are independent per side. A healthy side that already
      // matches the selected profile stays active; every non-matching side is
      // ended before its replacement is connected below.
      const hasDb = hasDbCredentials(profile);
      const hasSl = hasSlCredentials(profile);
      const dbTargetKey = dbConnectionKey(profile);
      const slTargetKey = slConnectionKey(profile);

      let dbAlreadyOnTarget = adapter.isConnected() && adapter.getConnectionKey() === dbTargetKey;
      let slAlreadyOnTarget = slAdapter.isConnected() && slAdapter.getConnectionKey() === slTargetKey;
      let existingDbPingMs: number | undefined;
      let existingSlPingMs: number | undefined;

      // A matching fingerprint says which profile created the adapter; it does
      // not prove the underlying socket/session is still alive. HANA timeouts
      // can drop the socket, and a rotated SL certificate invalidates the next
      // pinned request. Probe matching sides so calling connect_database is a
      // real recovery operation, not a permanent "already connected" no-op.
      if (dbAlreadyOnTarget) {
        const health = await adapter.checkConnection();
        existingDbPingMs = health.durationMs;
        if (!health.connected) {
          await adapter.disconnect();
          dbAlreadyOnTarget = false;
        }
      }
      if (slAlreadyOnTarget) {
        const health = await slAdapter.checkConnection();
        existingSlPingMs = health.durationMs;
        if (!health.connected) {
          await slAdapter.disconnect();
          slAlreadyOnTarget = false;
        }
      }

      // Tear down every side whose key no longer matches this profile, whether
      // or not the profile still configures it. Deleting the SL fields is how an
      // operator revokes Service Layer access, and a key that changed can never
      // match again, so an untouched session would otherwise stay usable until
      // the process restarted.
      //
      // Per-side teardown still upholds the invariant that DirectDb and the
      // Service Layer never point at different environments: after this pass a
      // connected side either already matched this profile, or is reconnected to
      // it below. Nothing can be left pointing anywhere else. A side that DOES
      // match is left alone, so rotating one side's credentials no longer bounces
      // the other.
      const previousDbName = adapter.getDbName() || slAdapter.getDbName();
      const dbStale = adapter.isConnected() && !dbAlreadyOnTarget;
      const slStale = slAdapter.isConnected() && !slAlreadyOnTarget;
      if (dbStale || slStale) {
        try {
          if (dbStale) await adapter.disconnect();
        } finally {
          // A DB pool close can fail. The stale Service Layer session must still
          // be torn down so a failed switch cannot leave it usable by mistake.
          if (slStale) await slAdapter.disconnect();
        }
        console.error(`[connect] Ended stale connection(s) from "${previousDbName}".`);
      }

      const everyConfiguredSideIsHealthy =
        (!hasDb || dbAlreadyOnTarget) && (!hasSl || slAlreadyOnTarget);
      if (everyConfiguredSideIsHealthy && (hasDb || hasSl)) {
        return {
          content: [{
            type: 'text' as const,
            text:
              `Already connected to "${profile.id}" (${profile.dbName}); all configured sides are healthy.` +
              `${existingDbPingMs != null ? `\nDirectDb: ${existingDbPingMs}ms` : ''}` +
              `${existingSlPingMs != null ? `\nServiceLayer: ${existingSlPingMs}ms` : ''}`,
          }],
        };
      }

      // --- Connect DirectDb (skip if already on target) ---
      let dbConnected = dbAlreadyOnTarget;
      let dbError: string | undefined;
      let dbPingMs: number | undefined = existingDbPingMs;
      let dbLoginAttempted = false;

      if (hasDb && !dbAlreadyOnTarget && !profile.dbPassword) {
        dbError =
          'dbPassword is missing or empty for this profile. No login was attempted, ' +
          'because an empty password can count towards database account lockout.';
      } else if (hasDb && !dbAlreadyOnTarget) {
        try {
          dbLoginAttempted = true;
          await adapter.init({
            server: profile.dbServer,
            database: profile.dbName,
            dbType: profile.dbType,
            username: profile.dbUser,
            password: profile.dbPassword,
            timeoutMs: config.queryTimeoutMs,
            connectionKey: dbTargetKey,
          });
          const check = await adapter.checkConnection();
          dbConnected = check.connected;
          dbPingMs = check.durationMs;
          if (!check.connected) {
            dbError = check.error;
            await adapter.disconnect();
          }
        } catch (err) {
          dbError = err instanceof Error ? err.message : String(err);
          await adapter.disconnect();
        }

        if (dbConnected) {
          resetFailures(profile.id, 'db');
        } else if (dbLoginAttempted) {
          recordFailure(profile.id, 'db');
        }
      }

      // --- Connect Service Layer (skip if already on target) ---
      let slConnected = slAlreadyOnTarget;
      let slError: string | undefined;
      let slPingMs: number | undefined = existingSlPingMs;
      let slLoginAttempted = false;
      let slTrustAction: ResolvedTlsConfig['trustAction'] | undefined;

      if (hasSl && !slAlreadyOnTarget && !profile.slPassword) {
        // An empty password is a guaranteed rejection, and SAP B1 counts it
        // against the account's lockout threshold like any other bad login.
        // Fail locally instead of spending one of the user's few attempts.
        slError =
          'slPassword is missing or empty for this profile. No login was attempted, ' +
          'because an empty password would count towards SAP B1 account lockout.';
      } else if (hasSl && !slAlreadyOnTarget) {
        try {
          const tls = await resolveServiceLayerTls(profile, config, trustStore, extra);
          slTrustAction = tls.trustAction;
          slLoginAttempted = true;
          await slAdapter.init({
            database: profile.dbName,
            username: profile.slUser!,
            password: profile.slPassword || '',
            url: profile.slUrl!,
            timeoutMs: config.slTimeoutMs,
            maxResponseChars: config.maxResultChars,
            tlsMode: tls.tlsMode,
            tlsServerName: tls.tlsServerName,
            certificateSha256: tls.certificateSha256,
            connectionKey: slTargetKey,
          });
          const check = await slAdapter.checkConnection();
          slConnected = check.connected;
          slPingMs = check.durationMs;
          if (!check.connected) {
            slError = check.error;
            await slAdapter.disconnect();
          }
        } catch (err) {
          slError = err instanceof Error ? err.message : String(err);
          await slAdapter.disconnect();
        }

        if (slConnected) {
          resetFailures(profile.id, 'sl');
        } else if (slLoginAttempted) {
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
          lines.push(`ServiceLayer TLS: ${slAdapter.getTlsStatus()}`);
          if (slTrustAction === 'approved-pin') lines.push(`ServiceLayer TLS trust: Certificate approved and saved to ${trustStore.getFilePath()}`);
          if (slTrustAction === 'replaced-pin') lines.push(`ServiceLayer TLS trust: Changed certificate approved and replaced in ${trustStore.getFilePath()}`);
          if (slTrustAction === 'migrated-pin') lines.push(`ServiceLayer TLS trust: Existing profile pin migrated to ${trustStore.getFilePath()}`);
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
      });
    },
  );
}
