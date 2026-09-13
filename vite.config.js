import { defineConfig } from 'vite';
import path from 'node:path';

export default defineConfig({
  root: 'public',
  publicDir: false,
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
});
