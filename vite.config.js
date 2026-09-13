import { defineConfig } from 'vite';
import path from 'node:path';

export default defineConfig({
  root: 'src/frontend',
  publicDir: false,
  build: {
    outDir: '../../dist',
    emptyOutDir: true,
  },
});
