import { createHash } from 'crypto';

// Tool callers always provide an endpoint relative to the configured Service
// Layer root. This synthetic root exists only to let WHATWG URL parsing detect
// traversal, absolute URLs, query strings and fragments; it must not encode an
// OData version because profiles may use /b1s/v1 (v3) or /b1s/v2 (v4).
const VALIDATION_ROOT_PATH = '/configured-service-layer-root/';
const VALIDATION_ROOT_URL = `https://mcp.invalid${VALIDATION_ROOT_PATH}`;

export interface ValidatedServiceLayerRequest {
  url: string;
  bodyJson?: string;
  bodyHash?: string;
  fields: string[];
}

function decodePath(path: string): string {
  try {
    return decodeURIComponent(path);
  } catch {
    throw new Error('Service Layer URL contains invalid percent-encoding.');
  }
}

export function validateServiceLayerRequest(
  method: 'GET' | 'PATCH',
  rawUrl: string,
  body: Record<string, unknown> | undefined,
  limits: { maxUrlLength: number; maxBodyChars: number },
): ValidatedServiceLayerRequest {
  const url = rawUrl.trim();
  if (!url) throw new Error('Service Layer URL is empty.');
  if (url.length > limits.maxUrlLength) {
    throw new Error(`Service Layer URL exceeds ${limits.maxUrlLength} characters.`);
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('/') || /[\\\u0000-\u001f\u007f]/.test(url)) {
    throw new Error('Service Layer URL must be a clean relative endpoint path.');
  }

  const parsed = new URL(url, VALIDATION_ROOT_URL);
  const decodedPath = decodePath(parsed.pathname);
  if (
    !parsed.pathname.startsWith(VALIDATION_ROOT_PATH) ||
    /(?:^|\/)\.\.?($|\/)/.test(decodedPath) ||
    /[\\\u0000-\u001f\u007f]/.test(decodedPath) ||
    parsed.hash
  ) {
    throw new Error('Service Layer URL may not escape the configured Service Layer root.');
  }

  const endpoint = decodedPath.slice(VALIDATION_ROOT_PATH.length);
  if (!endpoint || /^(?:Login|Logout|\$batch)(?:$|[(/?])/i.test(endpoint)) {
    throw new Error('This Service Layer endpoint is not permitted.');
  }

  if (method === 'PATCH') {
    if (parsed.search || parsed.hash || endpoint.includes('/')) {
      throw new Error('PATCH requires one directly keyed entity endpoint without navigation or query options.');
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*\(.+\)$/.test(endpoint)) {
      throw new Error('PATCH requires a keyed entity endpoint such as BusinessPartners(\'C0001\').');
    }
    if (!body || Object.keys(body).length === 0) {
      throw new Error('PATCH requires a non-empty JSON object body.');
    }
  } else if (body !== undefined) {
    throw new Error('GET requests must not include a body.');
  }

  if (!body) return { url, fields: [] };

  const bodyJson = JSON.stringify(body);
  if (bodyJson.length > limits.maxBodyChars) {
    throw new Error(`PATCH body exceeds ${limits.maxBodyChars} characters.`);
  }

  return {
    url,
    bodyJson,
    bodyHash: createHash('sha256').update(bodyJson).digest('hex'),
    fields: Object.keys(body).sort(),
  };
}
