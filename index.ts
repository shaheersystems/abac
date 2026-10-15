import { loadConfig } from './src/config.ts';
import { createDb } from './src/db/index.ts';
import { seedDatabase, DEMO_PASSWORD, SEED_ACCOUNTS } from './src/db/seed.ts';
import { createApp } from './src/http/app.ts';

const config = loadConfig();
const db = createDb(config.dataDir);

// First run on an empty data directory: lay down accounts, content and policy.
if ((await db.users.count()) === 0) {
    await seedDatabase(db);
    console.log(`Seeded a fresh database in ${config.dataDir}`);
}

const app = await createApp(config, db);
const removed = await app.services.sessions.purgeExpired();
if (removed > 0) console.log(`Purged ${removed} expired session(s).`);

const server = Bun.serve({
    hostname: config.host,
    port: config.port,
    fetch: app.fetch,
});

const roles = app.services.authz.ac.getRoles();
console.log(`
RBAC reference API — accesscontrol v3 over a JSON database
  listening   http://${server.hostname}:${server.port}
  data dir    ${config.dataDir}
  policy      ${roles.length} roles (${roles.join(', ')})${config.policyLocked ? ' [locked]' : ''}
  step-up     POST /auth/mfa/verify  code=${config.mfaCode}
  time travel ${config.allowTimeTravel ? 'enabled (X-Simulated-Now header)' : 'disabled'}

Demo accounts (password: ${DEMO_PASSWORD})
${SEED_ACCOUNTS.map((a) => `  ${a.email.padEnd(20)} ${a.roles.join(', ')}${a.disabled ? ' [disabled]' : ''}`).join('\n')}

Try:
  curl -s localhost:${server.port}/articles | head -30
  curl -s -XPOST localhost:${server.port}/auth/login -H 'content-type: application/json' \\
    -d '{"email":"aria@example.com","password":"${DEMO_PASSWORD}"}'
`);
