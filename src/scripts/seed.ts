import { loadConfig } from '../config.ts';
import { createDb } from '../db/index.ts';
import { DEMO_PASSWORD, seedDatabase, SEED_ACCOUNTS } from '../db/seed.ts';

const config = loadConfig();
const db = createDb(config.dataDir);
await seedDatabase(db);

console.log(`Database reset in ${config.dataDir}`);
console.log(`  ${SEED_ACCOUNTS.length} accounts, password: ${DEMO_PASSWORD}`);
for (const account of SEED_ACCOUNTS) {
    console.log(`  ${account.email.padEnd(20)} ${account.roles.join(', ')}${account.disabled ? ' [disabled]' : ''}`);
}
console.log('  policy snapshot written to policy.json');
