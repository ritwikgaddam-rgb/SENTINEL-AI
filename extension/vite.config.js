import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { copyFileSync } from 'node:fs';

function extensionFiles() {
  let outDir;
  return {
    name: 'sentinel-extension-files',
    apply: 'build',
    configResolved(config) { outDir = resolve(config.root, config.build.outDir); },
    closeBundle() {
      copyFileSync(resolve(__dirname, 'manifest.json'), resolve(outDir, 'manifest.json'));
      copyFileSync(resolve(__dirname, 'src/content/gmailOverlay.css'), resolve(outDir, 'gmailOverlay.css'));
    },
  };
}

export default defineConfig({
  plugins: [react(), extensionFiles()],
  base: './',
  build: {
    outDir: process.env.SENTINELAI_EXTENSION_OUT || 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        content: resolve(__dirname, 'src/content/content.js'),
        background: resolve(__dirname, 'src/background/background.js')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') return 'background.js';
          if (chunkInfo.name === 'content') return 'content.js';
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name && assetInfo.name.endsWith('.css')) {
            if (assetInfo.name.includes('gmailOverlay')) return 'gmailOverlay.css';
          }
          return 'assets/[name]-[hash][extname]';
        }
      }
    }
  }
});
