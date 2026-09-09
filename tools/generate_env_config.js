/**
 * GEOGRAPHY EDU - BUILD SCRIPT: SINH FILE CAU HINH TU .env
 *
 * Vi day la site tinh (khong bundler, khong backend), trinh duyet khong the
 * tu doc file .env. Script nay doc .env o thu muc goc va sinh ra
 * js/env-config.js (KHONG commit len Git - xem .gitignore) chua cac gia tri
 * that duoi dang `window.__ENV__`, de js/firebase-config.js va js/ai-chat.js
 * doc lai thay vi hardcode truc tiep trong ma nguon.
 *
 * Chay: node tools/generate_env_config.js  (hoac tu dong qua `npm run build`)
 */
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const envPath = path.join(rootDir, '.env');
const outputPath = path.join(rootDir, 'js', 'env-config.js');

const REQUIRED_KEYS = [
  'GEMINI_API_KEY',
  'FIREBASE_API_KEY',
  'FIREBASE_AUTH_DOMAIN',
  'FIREBASE_DATABASE_URL',
  'FIREBASE_PROJECT_ID',
  'FIREBASE_STORAGE_BUCKET',
  'FIREBASE_MESSAGING_SENDER_ID',
  'FIREBASE_APP_ID',
  'FIREBASE_MEASUREMENT_ID'
];

function parseEnvFile(content) {
  const env = {};
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || !line.includes('=')) continue;
    const [key, ...rest] = line.split('=');
    env[key.trim()] = rest.join('=').trim();
  }
  return env;
}

if (!fs.existsSync(envPath)) {
  console.error('[generate_env_config] Khong tim thay file .env o thu muc goc du an.');
  console.error('[generate_env_config] Hay copy .env.example thanh .env roi dien gia tri that truoc khi build.');
  process.exit(1);
}

const env = parseEnvFile(fs.readFileSync(envPath, 'utf-8'));

const missing = REQUIRED_KEYS.filter(k => !env[k]);
if (missing.length > 0) {
  console.warn('[generate_env_config] CANH BAO: .env dang thieu cac bien sau (se de trong):');
  missing.forEach(k => console.warn(`  - ${k}`));
}

const values = {};
for (const key of REQUIRED_KEYS) {
  values[key] = env[key] || '';
}

const fileContent = `/**
 * FILE TU DONG SINH - KHONG SUA TAY, KHONG COMMIT LEN GIT.
 * Duoc tao boi tools/generate_env_config.js tu file .env o thu muc goc.
 * Chay lai "npm run build" (hoac "node tools/generate_env_config.js") sau
 * khi thay doi .env de cap nhat file nay.
 */
window.__ENV__ = ${JSON.stringify(values, null, 2)};
`;

fs.writeFileSync(outputPath, fileContent, 'utf-8');
console.log(`[generate_env_config] Da sinh js/env-config.js tu .env (${REQUIRED_KEYS.length - missing.length}/${REQUIRED_KEYS.length} bien co gia tri).`);
