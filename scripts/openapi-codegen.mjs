#!/usr/bin/env node
/**
 * Regenerate typed OpenAPI surfaces for this app (paths + components).
 *
 * After the backend changes routes or DTOs:
 *   1. Export OpenAPI 3 JSON from each Swagger surface (Admin / Tenant / Chat), **or**
 *   2. Point env vars at a URL that returns raw JSON (not the Swagger UI HTML page).
 *
 * Examples:
 *   OPENAPI_ADMIN_URL=http://127.0.0.1:4040/... npm run codegen:api
 *   # or drop files at openapi/specs/admin.json, tenant.json, chat.json
 *
 * Outputs (committed or refreshed locally): src/types/openapi/{admin,tenant,chat}-openapi.ts
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'src/types/openapi');
const specDir = join(root, 'openapi/specs');

mkdirSync(outDir, { recursive: true });
mkdirSync(specDir, { recursive: true });

const surfaces = [
  { key: 'ADMIN', file: 'admin' },
  { key: 'TENANT', file: 'tenant' },
  { key: 'CHAT', file: 'chat' }
];

let ran = 0;
let failed = false;

for (const { key, file } of surfaces) {
  const envUrl = process.env[`OPENAPI_${key}_URL`];
  const localJson = join(specDir, `${file}.json`);
  const input = envUrl?.trim() || (existsSync(localJson) ? localJson : null);
  const outTs = join(outDir, `${file}-openapi.ts`);

  if (!input) {
    console.warn(
      `[codegen] Skip ${file}: set OPENAPI_${key}_URL or add openapi/specs/${file}.json`
    );
    continue;
  }

  const res = spawnSync('npx', ['openapi-typescript', input, '-o', outTs], {
    cwd: root,
    stdio: 'inherit',
    shell: true
  });

  if (res.status !== 0) {
    failed = true;
    console.error(`[codegen] Failed: ${file}`);
  } else {
    ran += 1;
    console.log(`[codegen] Wrote ${outTs}`);
  }
}

if (ran === 0) {
  console.log('[codegen] No inputs resolved — nothing generated (this is OK for fresh clones).');
  process.exit(0);
}

process.exit(failed ? 1 : 0);
