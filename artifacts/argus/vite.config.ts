import path from 'path';
import { fileURLToPath } from 'url';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = Number(process.env.PORT || '5173');
const basePath = process.env.BASE_PATH || '/';

const plugins: import('vite').Plugin[] = [react(), tailwindcss()];

try {
  const mod = await import('@replit/vite-plugin-runtime-error-modal');
  plugins.push(mod.default());
} catch {
  // Replit runtime error plugin not available, skip
}

if (process.env.NODE_ENV !== 'production' && process.env.REPL_ID !== undefined) {
  try {
    const cartMod = await import('@replit/vite-plugin-cartographer');
    plugins.push(cartMod.cartographer({ root: path.resolve(__dirname, '..') }));
  } catch { /* skip */ }
  try {
    const bannerMod = await import('@replit/vite-plugin-dev-banner');
    plugins.push(bannerMod.devBanner());
  } catch { /* skip */ }
}

export default defineConfig({
  base: basePath,
  cacheDir: path.resolve(__dirname, '../.vite-cache/argus'),
  plugins,
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@assets': path.resolve(__dirname, '..', '..', 'attached_assets'),
    },
    dedupe: ['react', 'react-dom'],
  },
  root: path.resolve(__dirname),
  build: {
    outDir: path.resolve(__dirname, 'dist/public'),
    emptyOutDir: true,
  },
  server: {
    port,
    strictPort: true,
    host: '0.0.0.0',
    allowedHosts: true,
    fs: {
      strict: true,
    },
    proxy: {
      '/api': {
        target: process.env.ARGUS_API_URL || 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
  preview: {
    port,
    host: '0.0.0.0',
    allowedHosts: true,
  },
});
