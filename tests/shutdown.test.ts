import { describe, it, expect, vi, afterEach } from 'vitest';
import { createShutdown } from '../src/shutdown.js';

function side(disconnect: () => Promise<void> = () => Promise.resolve()) {
  return { disconnect: vi.fn(disconnect) };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('createShutdown', () => {
  it('disconnects both sides, then exits 0', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = side();
    const slAdapter = side();
    const exit = vi.fn();

    await createShutdown({ adapter, slAdapter, exit })('test');

    expect(adapter.disconnect).toHaveBeenCalledOnce();
    expect(slAdapter.disconnect).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenCalledWith(0);
    expect(exit.mock.invocationCallOrder[0]).toBeGreaterThan(
      slAdapter.disconnect.mock.invocationCallOrder[0],
    );
  });

  it('still exits when one side rejects', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = side(() => Promise.reject(new Error('pool close failed')));
    const slAdapter = side();
    const exit = vi.fn();

    await createShutdown({ adapter, slAdapter, exit })('test');

    expect(slAdapter.disconnect).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenCalledWith(0);
  });

  it('exits after the deadline when a disconnect never settles', async () => {
    vi.useFakeTimers();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = side(() => new Promise<void>(() => {}));
    const slAdapter = side();
    const exit = vi.fn();

    const done = createShutdown({ adapter, slAdapter, exit, timeoutMs: 1_000 })('test');
    await vi.advanceTimersByTimeAsync(999);
    expect(exit).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await done;
    expect(exit).toHaveBeenCalledWith(0);
  });

  it('is idempotent across repeated triggers', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = side();
    const slAdapter = side();
    const exit = vi.fn();
    const shutdown = createShutdown({ adapter, slAdapter, exit });

    await Promise.all([shutdown('SIGTERM'), shutdown('stdin closed')]);
    await shutdown('transport closed');

    expect(adapter.disconnect).toHaveBeenCalledOnce();
    expect(slAdapter.disconnect).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenCalledOnce();
  });
});
