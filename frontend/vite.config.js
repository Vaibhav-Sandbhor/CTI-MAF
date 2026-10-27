import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Use relative paths for Electron production builds
  base: './',
  build: {
    outDir: 'dist',
    // Ensure assets are bundled correctly for Electron
    assetsDir: 'assets',
    // Generate sourcemaps for debugging
    sourcemap: process.env.NODE_ENV === 'development',
  },
  server: {
    port: 5173,
    strictPort: true,
  },
})
