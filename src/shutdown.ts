// ============================================================================
// b1-mcp-server — Graceful shutdown
// ============================================================================
//
// The SDK's stdio transport only pauses stdin when it closes; it never exits.
// Measured against real servers with both sides connected, then stdin closed:
//   - MS SQL: the mssql pool keeps the event loop alive, so the process never
//     exits — an orphan that holds its DB connection until killed.
//   - HANA: the process exits on its own (hana-client does not hold the loop),
//     but without a Service Layer Logout.
// Either way the B1 session was left to expire server-side, and SIGTERM skipped
// the Logout too.
//
// Every exit path (transport close, stdin EOF, SIGTERM, SIGINT) routes through
// one idempotent function: disconnect both sides, bounded by a deadline so an
// unreachable host cannot keep the process alive, then exit.
// ============================================================================

interface Disconnectable {
  disconnect(): Promise<void>;
}

export interface ShutdownDeps {
  adapter: Disconnectable;
  slAdapter: Disconnectable;
  exit: (code: number) => void;
  /** Upper bound for both disconnects together. Default 5 000 ms. */
  timeoutMs?: number;
}

export function createShutdown(deps: ShutdownDeps): (reason: string) => Promise<void> {
  const timeoutMs = deps.timeoutMs ?? 5_000;
  let running: Promise<void> | undefined;

  return (reason: string) => {
    running ??= (async () => {
      console.error(`[b1-mcp-server] Shutting down (${reason}).`);

      let timer: NodeJS.Timeout | undefined;
      const deadline = new Promise<void>((resolve) => {
        timer = setTimeout(() => {
          console.error(`[b1-mcp-server] Disconnect did not finish within ${timeoutMs}ms; exiting anyway.`);
          resolve();
        }, timeoutMs);
      });

      try {
        await Promise.race([
          Promise.allSettled([deps.adapter.disconnect(), deps.slAdapter.disconnect()]),
          deadline,
        ]);
      } finally {
        clearTimeout(timer);
        deps.exit(0);
      }
    })();
    return running;
  };
}
