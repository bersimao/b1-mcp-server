import { describe, expect, it } from 'vitest';
import { OperationCoordinator } from '../../src/security/operationCoordinator.js';

describe('OperationCoordinator', () => {
  it('serialises concurrent operations in arrival order', async () => {
    const coordinator = new OperationCoordinator();
    const events: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });

    const first = coordinator.runExclusive(async () => {
      events.push('first:start');
      await firstGate;
      events.push('first:end');
    });
    const second = coordinator.runExclusive(async () => {
      events.push('second:start');
      events.push('second:end');
    });

    await Promise.resolve();
    expect(events).toEqual(['first:start']);
    releaseFirst();
    await Promise.all([first, second]);
    expect(events).toEqual(['first:start', 'first:end', 'second:start', 'second:end']);
  });
});
