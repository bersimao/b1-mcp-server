import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

export interface ServiceLayerCertificateRecord {
  certificateSha256: string;
  serverName?: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  approvedAt: string;
}

interface TrustFile {
  version: 1;
  origins: Record<string, ServiceLayerCertificateRecord>;
}

export class ServiceLayerTrustStore {
  constructor(private readonly filePath: string) {}

  getFilePath(): string {
    return this.filePath;
  }

  get(origin: string): ServiceLayerCertificateRecord | undefined {
    return this.read().origins[origin];
  }

  approve(origin: string, record: Omit<ServiceLayerCertificateRecord, 'approvedAt'>): void {
    const trust = this.read();
    trust.origins[origin] = { ...record, approvedAt: new Date().toISOString() };
    this.write(trust);
  }

  private read(): TrustFile {
    try {
      if (process.platform !== 'win32') {
        const mode = statSync(this.filePath).mode & 0o777;
        if ((mode & 0o077) !== 0) {
          throw new Error(
            `Refusing Service Layer trust store ${this.filePath}: permissions are ${mode.toString(8)}, expected 600.`,
          );
        }
      }
      const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as Partial<TrustFile>;
      if (parsed.version !== 1 || !parsed.origins || typeof parsed.origins !== 'object' || Array.isArray(parsed.origins)) {
        throw new Error(`Invalid Service Layer trust store format in ${this.filePath}.`);
      }
      return { version: 1, origins: { ...parsed.origins } };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { version: 1, origins: {} };
      }
      throw error;
    }
  }

  private write(trust: TrustFile): void {
    const directory = dirname(this.filePath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporaryPath = `${this.filePath}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temporaryPath, `${JSON.stringify(trust, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      });
      if (process.platform !== 'win32') chmodSync(temporaryPath, 0o600);
      renameSync(temporaryPath, this.filePath);
      if (process.platform !== 'win32') chmodSync(this.filePath, 0o600);
    } catch (error) {
      try { unlinkSync(temporaryPath); } catch { /* best-effort temporary cleanup */ }
      throw error;
    }
  }
}
