// ============================================================================
// Tests: UPDATE Sanitiser
// ============================================================================

import { describe, it, expect } from 'vitest';
import { sanitiseUpdate } from '../../src/sanitisation/updateSanitiser.js';

// ---------------------------------------------------------------------------
// Layer 1: Input Validation
// ---------------------------------------------------------------------------

describe('UPDATE Sanitiser — Layer 1: Input Validation', () => {
  it('rejects queries with null bytes', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1\x00');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('null bytes');
  });

  it('rejects queries with non-printable control characters', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1\x07');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('non-printable');
  });

  it('rejects queries exceeding max length', () => {
    const longQuery = 'UPDATE T SET X = \'' + 'A'.repeat(9000) + '\'';
    const r = sanitiseUpdate(longQuery);
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('maximum length');
  });

  it('allows normal UPDATE queries', () => {
    const r = sanitiseUpdate('UPDATE MY_TABLE SET "Status" = \'active\' WHERE "Id" = 1');
    expect(r.safe).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Layer 2: Structure Validation
// ---------------------------------------------------------------------------

describe('UPDATE Sanitiser — Layer 2: Structure Validation', () => {
  it('rejects UNION in UPDATE', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = (SELECT 1 UNION SELECT 2) WHERE 1=1'
    );
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('UNION');
  });

  it('rejects INTERSECT', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = 1 INTERSECT SELECT 2'
    );
    expect(r.safe).toBe(false);
  });

  it('rejects EXCEPT', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = 1 EXCEPT SELECT 2'
    );
    expect(r.safe).toBe(false);
  });

  it('does not flag UNION inside string literals', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = \'UNION test\' WHERE 1=1'
    );
    expect(r.safe).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Layer 3: Dangerous Pattern Detection
// ---------------------------------------------------------------------------

describe('UPDATE Sanitiser — Layer 3: Dangerous Patterns', () => {
  it('blocks xp_cmdshell', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; EXEC xp_cmdshell \'dir\'');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('xp_cmdshell');
  });

  it('blocks sp_executesql', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; EXEC sp_executesql N\'SELECT 1\'');
    expect(r.safe).toBe(false);
  });

  it('blocks EXEC(', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; EXEC(\'DROP TABLE ORDR\')');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('EXEC_dynamic');
  });

  it('blocks CALL (HANA procedure invocation)', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; CALL MY_DANGEROUS_PROC()');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('CALL_proc');
  });

  it('blocks WAITFOR DELAY', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; WAITFOR DELAY \'00:00:05\'');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('WAITFOR_DELAY');
  });

  it('blocks OPENROWSET', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = (SELECT * FROM OPENROWSET(\'SQLOLEDB\', \'server\', \'SELECT 1\'))'
    );
    expect(r.safe).toBe(false);
  });

  it('blocks BULK INSERT', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; BULK INSERT T FROM \'file.csv\'');
    expect(r.safe).toBe(false);
  });

  it('blocks hidden CREATE TABLE', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; CREATE TABLE evil (id INT)');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('CREATE_hidden');
  });

  it('blocks hidden DROP TABLE', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; DROP TABLE ORDR');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('DROP_hidden');
  });

  it('blocks GRANT', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1; GRANT SELECT ON T TO public');
    expect(r.safe).toBe(false);
  });

  it('does NOT flag dangerous keywords inside string literals', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = \'xp_cmdshell is dangerous\' WHERE 1=1'
    );
    expect(r.safe).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Layer 4: Comment Blocking
// ---------------------------------------------------------------------------

describe('UPDATE Sanitiser — Layer 4: Comment Blocking', () => {
  it('blocks single-line comments', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1 -- sneaky comment');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('comments');
  });

  it('blocks multi-line comments', () => {
    const r = sanitiseUpdate('UPDATE T SET X = 1 /* hidden */ WHERE 1=1');
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('comments');
  });

  it('does NOT flag -- inside string literals', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = \'value -- not a comment\' WHERE 1=1'
    );
    expect(r.safe).toBe(true);
  });

  it('does NOT flag /* inside string literals', () => {
    const r = sanitiseUpdate(
      'UPDATE T SET X = \'value /* not a comment */\' WHERE 1=1'
    );
    expect(r.safe).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Clean queries — should all pass
// ---------------------------------------------------------------------------

describe('UPDATE Sanitiser — Clean queries', () => {
  it('passes a normal UDF update', () => {
    const r = sanitiseUpdate(
      'UPDATE ORDR SET "U_CustomField" = \'new value\' WHERE "DocEntry" = 100'
    );
    expect(r.safe).toBe(true);
  });

  it('passes an update with numeric value', () => {
    const r = sanitiseUpdate(
      'UPDATE MY_TABLE SET "Count" = 42 WHERE "Id" = 1'
    );
    expect(r.safe).toBe(true);
  });

  it('passes an update setting NULL', () => {
    const r = sanitiseUpdate(
      'UPDATE MY_TABLE SET "Notes" = NULL WHERE "Id" = 1'
    );
    expect(r.safe).toBe(true);
  });

  it('passes an update with multiple SET columns', () => {
    const r = sanitiseUpdate(
      'UPDATE MY_TABLE SET "A" = 1, "B" = \'two\', "C" = NULL WHERE "D" = 4'
    );
    expect(r.safe).toBe(true);
  });

  it('passes an update with escaped quotes in value', () => {
    const r = sanitiseUpdate(
      'UPDATE MY_TABLE SET "Name" = \'O\'\'Brien\' WHERE "Id" = 1'
    );
    expect(r.safe).toBe(true);
  });
});
