import { createHash } from 'crypto';

// Tool callers always provide an endpoint relative to the configured Service
// Layer root. This synthetic root exists only to let WHATWG URL parsing detect
// traversal, absolute URLs, query strings and fragments; it must not encode an
// OData version because profiles may use /b1s/v1 (v3) or /b1s/v2 (v4).
const VALIDATION_ROOT_PATH = '/configured-service-layer-root/';
const VALIDATION_ROOT_URL = `https://mcp.invalid${VALIDATION_ROOT_PATH}`;

/** Every verb execute_service_layer can speak. PUT is absent on purpose: it
 *  replaces the whole entity, so any field the body omits is wiped. */
export const SERVICE_LAYER_METHODS = ['GET', 'PATCH', 'POST', 'DELETE'] as const;
export type ServiceLayerMethod = typeof SERVICE_LAYER_METHODS[number];

/** Allowed verbs for a profile without slAllowedMethods — the pre-allowlist behaviour. */
export const DEFAULT_SL_ALLOWED_METHODS: readonly ServiceLayerMethod[] = ['GET', 'PATCH'];

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
  method: ServiceLayerMethod,
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

  const keyedEntity = /^[A-Za-z_][A-Za-z0-9_]*\(.+\)$/;
  if (method === 'PATCH' || method === 'DELETE') {
    if (parsed.search || endpoint.includes('/')) {
      throw new Error(`${method} requires one directly keyed entity endpoint without navigation or query options.`);
    }
    if (!keyedEntity.test(endpoint)) {
      throw new Error(`${method} requires a keyed entity endpoint such as BusinessPartners('C0001').`);
    }
  } else if (method === 'POST') {
    // An entity set or service operation (Orders, CompanyService_GetCompanyInfo),
    // or one bound action on a keyed entity (Orders(12)/Close). The key accepts
    // quoted spans verbatim but no bare ( ) / outside them, so a longer
    // navigation such as A(1)/B(2)/C cannot pass as one key.
    if (parsed.search || !/^[A-Za-z_][A-Za-z0-9_]*(?:\((?:'(?:[^']|'')*'|[^'()/])+\)\/[A-Za-z_][A-Za-z0-9_]*)?$/.test(endpoint)) {
      throw new Error('POST requires an entity set, a service operation, or a keyed entity action such as Orders(12)/Close, without query options.');
    }
  }

  if (method === 'PATCH') {
    if (!body || Object.keys(body).length === 0) {
      throw new Error('PATCH requires a non-empty JSON object body.');
    }
  } else if ((method === 'GET' || method === 'DELETE') && body !== undefined) {
    throw new Error(`${method} requests must not include a body.`);
  }

  if (!body) return { url, fields: [] };

  const bodyJson = JSON.stringify(body);
  if (bodyJson.length > limits.maxBodyChars) {
    throw new Error(`${method} body exceeds ${limits.maxBodyChars} characters.`);
  }

  return {
    url,
    bodyJson,
    bodyHash: createHash('sha256').update(bodyJson).digest('hex'),
    fields: Object.keys(body).sort(),
  };
}
