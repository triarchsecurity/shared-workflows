import { fileURLToPath } from 'node:url';

// Absolute path to a fixture repo root, cwd-independent.
export function fixture(name) {
  return fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
}
