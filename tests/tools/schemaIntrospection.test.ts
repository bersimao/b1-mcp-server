// ============================================================================
// get_schema_info — the filter must never reach the SQL text
// ============================================================================
//
// This is the one SQL path that does not go through the guardrail engine, so
// the only thing standing between a hostile filter and the database is the `?`
// bind. These tests fail the moment someone reintroduces interpolation.
// ============================================================================

import { describe, it, expect } from 'vitest';
import { buildSchemaQuery } from '../../src/tools/schemaIntrospection.js';
import { DbType } from '../../src/types/index.js';

const HOSTILE = "OITM' ; DROP TABLE OITM --";
const dbTypes: DbType[] = ['hana', 'mssql'];
const filtered = ['tables', 'columns', 'procedures'];

describe('buildSchemaQuery', () => {
  for (const dbType of dbTypes) {
    describe(dbType, () => {
      for (const objectType of filtered) {
        it(`binds the filter for ${objectType} instead of interpolating it`, () => {
          const { query, params } = buildSchemaQuery(objectType, HOSTILE, dbType);
          expect(query).not.toContain('DROP');
          expect(query).not.toContain('OITM');
          expect(query).toContain('?');
          expect(params).toEqual([HOSTILE]);
        });
      }

      it('omits the LIKE clause and params when no filter is given', () => {
        const { query, params } = buildSchemaQuery('tables', undefined, dbType);
        expect(query).not.toContain('?');
        expect(params).toEqual([]);
      });

      it('asks for a table name when columns is called without a filter', () => {
        const { query, params } = buildSchemaQuery('columns', undefined, dbType);
        expect(query).toContain('provide a table name');
        expect(params).toEqual([]);
      });

      it('rejects an unknown objectType', () => {
        const { query, params } = buildSchemaQuery('sequences', 'x', dbType);
        expect(query).toContain('Unsupported objectType');
        expect(params).toEqual([]);
      });

      it('emits exactly one placeholder per bound param', () => {
        for (const objectType of filtered) {
          const { query, params } = buildSchemaQuery(objectType, 'OITM', dbType);
          expect(query.split('?').length - 1).toBe(params.length);
        }
      });
    });
  }
});
