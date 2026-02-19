import { defineConfig } from 'vite'
import typescript from '@rollup/plugin-typescript';
import environment from 'vite-plugin-environment';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    typescript({
      inlineSources: true,
    }),
    environment("all", { prefix: "CANISTER_" }),
    environment("all", { prefix: "DFX_" }),
  ],
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  root: "./",
  server: {
    hmr: false
  }
})