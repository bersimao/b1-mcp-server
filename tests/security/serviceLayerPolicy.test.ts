import { describe, expect, it } from 'vitest';
import { validateServiceLayerRequest } from '../../src/security/serviceLayerPolicy.js';

const limits = { maxUrlLength: 2048, maxBodyChars: 100 };

describe('validateServiceLayerRequest', () => {
  it('accepts a directly keyed PATCH and fingerprints its exact body', () => {
    const result = validateServiceLayerRequest(
      'PATCH',
      "BusinessPartners('C0001')",
      { CreditLimit: 100, U_Status: 'A' },
      limits,
    );
    expect(result.fields).toEqual(['CreditLimit', 'U_Status']);
    expect(result.bodyHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('validates relative endpoints without coupling them to OData v1 or v2', () => {
    const result = validateServiceLayerRequest('GET', 'Items?$select=ItemCode&$top=1', undefined, limits);
    expect(result.url).toBe('Items?$select=ItemCode&$top=1');
  });

  it.each([
    'https://evil.example/BusinessPartners(1)',
    '/BusinessPartners(1)',
    '../../admin',
    '%2e%2e/%2e%2e/admin',
    'BusinessPartners(1)/Orders',
    'BusinessPartners(1)?x=1',
    'BusinessPartners(1)#fragment',
    'BusinessPartners%5c(1)',
    '$batch',
    'Login',
    'Login(1)',
  ])('rejects unsafe PATCH endpoint %s', (url) => {
    expect(() => validateServiceLayerRequest('PATCH', url, { U_X: 1 }, limits)).toThrow();
  });

  it('rejects empty and oversized PATCH bodies', () => {
    expect(() => validateServiceLayerRequest('PATCH', 'Items(1)', {}, limits)).toThrow('non-empty');
    expect(() => validateServiceLayerRequest('PATCH', 'Items(1)', { X: 'x'.repeat(101) }, limits)).toThrow('exceeds');
  });

  it('rejects a body on GET', () => {
    expect(() => validateServiceLayerRequest('GET', 'Items?$top=1', { X: 1 }, limits)).toThrow('must not include');
  });
});
