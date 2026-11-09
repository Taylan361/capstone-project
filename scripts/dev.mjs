import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = process.env.PYTHON || 'python3';
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const children = [];
let stopping = false;

function start(command, args, label) {
  const child = spawn(command, args, { cwd: root, stdio: 'inherit' });
  children.push(child);
  child.on('error', (error) => {
    console.error(`${label} could not start: ${error.message}`);
    stop(1);
  });
  child.on('exit', (code) => {
    if (!stopping) stop(code ?? 1);
  });
  return child;
}

function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (!child.killed) child.kill('SIGTERM');
  }
  setTimeout(() => process.exit(code), 250).unref();
}

async function hasHealthyBackend() {
  try {
    const response = await fetch('http://127.0.0.1:8765/api/health', {
      signal: AbortSignal.timeout(500),
    });
    if (!response.ok) return false;
    const health = await response.json();
    return health.status === 'ok';
  } catch {
    return false;
  }
}

process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));

if (await hasHealthyBackend()) {
  console.log('Using the existing local scanner API at http://127.0.0.1:8765');
} else {
  start(python, ['server.py'], 'Local scanner');
}
start(npm, ['--prefix', 'web', 'run', 'dev'], 'React dashboard');
