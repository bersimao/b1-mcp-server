// Shared by the scripts: load the connection profiles, and when the file is
// encrypted and locked, wait for `creds unlock` from the user's terminal on the
// same private socket the server uses.

import { ConnectionManager } from '../src/config/connectionManager.js';
import { UnlockListener } from '../src/config/unlockSocket.js';

export async function loadProfiles(): Promise<ConnectionManager> {
  const manager = new ConnectionManager(process.env.MCP_CONNECTIONS_FILE || undefined);
  manager.load();
  if (manager.getState() !== 'locked') {
    const blocked = manager.blockedReason();
    if (blocked) console.error(blocked);
    return manager;
  }

  const unlocked = new Promise<void>((resolve) => {
    const target = {
      getEncryptedFilePath: () => manager.getEncryptedFilePath(),
      unlock: async (passphrase: string) => {
        const ok = await manager.unlock(passphrase);
        if (ok) resolve();
        return ok;
      },
    };
    const listener = new UnlockListener({ target, log: () => {} });
    process.once('exit', () => listener.close());
    listener.ensure().catch((err: Error) => {
      console.error(`Could not open the unlock socket: ${err.message}`);
      process.exit(1);
    });
  });
  // credsCommand() would name this script (tsx's argv[1]); point at the build instead.
  console.error('Credentials are encrypted. Unlock them from another terminal, in the repo: node dist/index.js creds unlock');
  await unlocked;
  console.error('Unlocked.');
  return manager;
}
