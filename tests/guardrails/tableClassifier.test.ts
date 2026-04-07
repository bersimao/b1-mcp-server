// ============================================================================
// Tests: Table Classifier
// ============================================================================

import { describe, it, expect } from 'vitest';
import {
  classifyTable,
  cleanTableName,
  stripSchemaPrefix,
  stripQuotes,
  isUserDefinedField,
} from '../../src/guardrails/tableClassifier.js';
import { TableType } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// stripSchemaPrefix
// ---------------------------------------------------------------------------

describe('stripSchemaPrefix', () => {
  it('returns the table name when there is no schema prefix', () => {
    expect(stripSchemaPrefix('ORDR')).toBe('ORDR');
  });

  it('strips a single schema prefix', () => {
    expect(stripSchemaPrefix('dbo.ORDR')).toBe('ORDR');
  });

  it('strips database + schema prefix', () => {
    expect(stripSchemaPrefix('SBO_Demo.dbo.ORDR')).toBe('ORDR');
  });

  it('handles quoted schema components', () => {
    expect(stripSchemaPrefix('"SBO_Demo"."dbo"."ORDR"')).toBe('"ORDR"');
  });

  it('handles bracket-quoted schema components', () => {
    expect(stripSchemaPrefix('[SBO_Demo].[dbo].[ORDR]')).toBe('[ORDR]');
  });

  it('handles mixed quoting styles', () => {
    expect(stripSchemaPrefix('"SBO_Demo".dbo.[ORDR]')).toBe('[ORDR]');
  });

  it('handles @ prefixed tables with schema', () => {
    expect(stripSchemaPrefix('dbo.@MY_UDT')).toBe('@MY_UDT');
  });

  it('handles temp tables with schema', () => {
    expect(stripSchemaPrefix('dbo.#temp_table')).toBe('#temp_table');
  });
});

// ---------------------------------------------------------------------------
// stripQuotes
// ---------------------------------------------------------------------------

describe('stripQuotes', () => {
  it('removes double quotes', () => {
    expect(stripQuotes('"ORDR"')).toBe('ORDR');
  });

  it('removes brackets', () => {
    expect(stripQuotes('[ORDR]')).toBe('ORDR');
  });

  it('removes backticks', () => {
    expect(stripQuotes('`ORDR`')).toBe('ORDR');
  });

  it('does not modify unquoted names', () => {
    expect(stripQuotes('ORDR')).toBe('ORDR');
  });

  it('trims whitespace', () => {
    expect(stripQuotes('  "ORDR"  ')).toBe('ORDR');
  });

  it('preserves @ prefix', () => {
    expect(stripQuotes('"@MY_TABLE"')).toBe('@MY_TABLE');
  });

  it('preserves # prefix', () => {
    expect(stripQuotes('"#temp"')).toBe('#temp');
  });
});

// ---------------------------------------------------------------------------
// cleanTableName
// ---------------------------------------------------------------------------

describe('cleanTableName', () => {
  it('handles plain table name', () => {
    expect(cleanTableName('ORDR')).toBe('ORDR');
  });

  it('handles full schema-qualified quoted name', () => {
    expect(cleanTableName('"SBO_Demo"."dbo"."ORDR"')).toBe('ORDR');
  });

  it('handles bracket-quoted schema-qualified name', () => {
    expect(cleanTableName('[SBO_Demo].[dbo].[ORDR]')).toBe('ORDR');
  });

  it('handles simple schema.table', () => {
    expect(cleanTableName('dbo.ORDR')).toBe('ORDR');
  });

  it('handles quoted table without schema', () => {
    expect(cleanTableName('"ORDR"')).toBe('ORDR');
  });
});

// ---------------------------------------------------------------------------
// classifyTable — SAP_CORE
// ---------------------------------------------------------------------------

describe('classifyTable — SAP_CORE', () => {
  const coreExamples = [
    'ORDR', 'OITM', 'INV1', 'OINV', 'OPCH', 'OITW', 'OADM',
    'JDT1', 'OJDT', 'OACT', 'OCRD', 'PCH1',
  ];

  for (const table of coreExamples) {
    it(`classifies "${table}" as SAP_CORE`, () => {
      expect(classifyTable(table)).toBe(TableType.SAP_CORE);
    });
  }

  it('classifies short names (3 chars) as SAP_CORE', () => {
    expect(classifyTable('JDT')).toBe(TableType.SAP_CORE);
  });

  it('classifies 2-char names as SAP_CORE', () => {
    expect(classifyTable('AB')).toBe(TableType.SAP_CORE);
  });

  it('classifies 1-char names as SAP_CORE', () => {
    expect(classifyTable('X')).toBe(TableType.SAP_CORE);
  });

  it('classifies quoted core table names correctly', () => {
    expect(classifyTable('"ORDR"')).toBe(TableType.SAP_CORE);
    expect(classifyTable('[ORDR]')).toBe(TableType.SAP_CORE);
    expect(classifyTable('`ORDR`')).toBe(TableType.SAP_CORE);
  });

  it('classifies schema-qualified core table names correctly', () => {
    expect(classifyTable('dbo.ORDR')).toBe(TableType.SAP_CORE);
    expect(classifyTable('"SBO_Demo"."dbo"."ORDR"')).toBe(TableType.SAP_CORE);
    expect(classifyTable('[SBO_Demo].[dbo].[ORDR]')).toBe(TableType.SAP_CORE);
  });

  it('classifies empty string as SAP_CORE (deny-by-default)', () => {
    expect(classifyTable('')).toBe(TableType.SAP_CORE);
  });
});

// ---------------------------------------------------------------------------
// classifyTable — SAP_USER
// ---------------------------------------------------------------------------

describe('classifyTable — SAP_USER', () => {
  it('classifies @-prefixed tables', () => {
    expect(classifyTable('@MY_UDT')).toBe(TableType.SAP_USER);
    expect(classifyTable('@CUSTOM_TABLE')).toBe(TableType.SAP_USER);
    expect(classifyTable('@A')).toBe(TableType.SAP_USER);
  });

  it('classifies quoted @-prefixed tables', () => {
    expect(classifyTable('"@MY_UDT"')).toBe(TableType.SAP_USER);
    expect(classifyTable('[@MY_UDT]')).toBe(TableType.SAP_USER);
  });

  it('classifies schema-qualified @-prefixed tables', () => {
    expect(classifyTable('dbo.@MY_UDT')).toBe(TableType.SAP_USER);
    expect(classifyTable('"SBO_Demo"."dbo"."@MY_UDT"')).toBe(TableType.SAP_USER);
  });
});

// ---------------------------------------------------------------------------
// classifyTable — CUSTOM
// ---------------------------------------------------------------------------

describe('classifyTable — CUSTOM', () => {
  it('classifies tables with >4 chars and no @ as CUSTOM', () => {
    expect(classifyTable('INVENTORY_AUDIT')).toBe(TableType.CUSTOM);
    expect(classifyTable('MY_CUSTOM_TABLE')).toBe(TableType.CUSTOM);
    expect(classifyTable('ABCDE')).toBe(TableType.CUSTOM);
  });

  it('classifies exactly 5-char names as CUSTOM', () => {
    expect(classifyTable('TABLS')).toBe(TableType.CUSTOM);
  });

  it('classifies quoted custom tables', () => {
    expect(classifyTable('"INVENTORY_AUDIT"')).toBe(TableType.CUSTOM);
  });
});

// ---------------------------------------------------------------------------
// classifyTable — TEMP
// ---------------------------------------------------------------------------

describe('classifyTable — TEMP', () => {
  it('classifies #-prefixed tables as TEMP', () => {
    expect(classifyTable('#temp_data')).toBe(TableType.TEMP);
    expect(classifyTable('#t')).toBe(TableType.TEMP);
  });

  it('classifies ##-prefixed tables as TEMP', () => {
    expect(classifyTable('##global_temp')).toBe(TableType.TEMP);
  });

  it('classifies quoted temp tables', () => {
    expect(classifyTable('"#temp_data"')).toBe(TableType.TEMP);
  });
});

// ---------------------------------------------------------------------------
// isUserDefinedField
// ---------------------------------------------------------------------------

describe('isUserDefinedField', () => {
  it('identifies U_ prefixed fields', () => {
    expect(isUserDefinedField('U_CustomField')).toBe(true);
    expect(isUserDefinedField('U_X')).toBe(true);
  });

  it('is case-insensitive', () => {
    expect(isUserDefinedField('u_customfield')).toBe(true);
    expect(isUserDefinedField('u_X')).toBe(true);
  });

  it('handles quoted field names', () => {
    expect(isUserDefinedField('"U_CustomField"')).toBe(true);
    expect(isUserDefinedField('[U_CustomField]')).toBe(true);
  });

  it('rejects non-UDF fields', () => {
    expect(isUserDefinedField('CardCode')).toBe(false);
    expect(isUserDefinedField('DocEntry')).toBe(false);
    expect(isUserDefinedField('UserName')).toBe(false);
    expect(isUserDefinedField('U')).toBe(false); // Just "U", no underscore
  });
});
