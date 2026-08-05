// Serialises connection switches and tool operations over the mutable
// DirectDb/Service Layer singletons. This prevents cross-profile races and
// also provides a hard concurrency ceiling for client database work.
export class OperationCoordinator {
  private tail: Promise<void> = Promise.resolve();

  async runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}
