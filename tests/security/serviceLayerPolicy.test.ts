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

  it.each([
    'Orders',
    'CompanyService_GetCompanyInfo',
    'Orders(12)/Close',
    "BusinessPartners('C/1')/Cancel",
    "ProductTrees(Code='A''B')/Cancel",
  ])('accepts POST endpoint %s', (url) => {
    expect(validateServiceLayerRequest('POST', url, undefined, limits).url).toBe(url);
  });

  it.each([
    'Orders?$select=DocEntry',
    'Orders(1)/DocumentLines(2)/Close',
    'A(1)/B(2)/C',
    'Orders/Close',
    'Orders(12)/Close/Again',
    'Login',
    'Logout',
    '$batch',
    '../Login',
  ])('rejects POST endpoint %s', (url) => {
    expect(() => validateServiceLayerRequest('POST', url, { X: 1 }, limits)).toThrow();
  });

  it('fingerprints a POST body and allows a bodyless action', () => {
    expect(validateServiceLayerRequest('POST', 'Orders', { CardCode: 'C1' }, limits).bodyHash).toMatch(/^[a-f0-9]{64}$/);
    expect(validateServiceLayerRequest('POST', 'Orders(1)/Close', undefined, limits).bodyHash).toBeUndefined();
  });

  it('allows DELETE only on a directly keyed entity, without a body', () => {
    expect(validateServiceLayerRequest('DELETE', "Items('A1')", undefined, limits).url).toBe("Items('A1')");
    expect(() => validateServiceLayerRequest('DELETE', 'Items', undefined, limits)).toThrow('keyed');
    expect(() => validateServiceLayerRequest('DELETE', 'Items(1)/ItemPrices', undefined, limits)).toThrow();
    expect(() => validateServiceLayerRequest('DELETE', 'Items(1)?x=1', undefined, limits)).toThrow();
    expect(() => validateServiceLayerRequest('DELETE', 'Items(1)', { X: 1 }, limits)).toThrow('must not include');
  });
});
