import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from 'tailwindcss'
import autoprefixer from "autoprefixer";
import css from 'rollup-plugin-css-only';
import typescript from '@rollup/plugin-typescript';
import environment from 'vite-plugin-environment';
import path from 'path';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    svelte(),
    css({ output: "bundle.css" }),
    typescript({
      inlineSources: true,
    }),
    environment("all", { prefix: "CANISTER_" }),
    environment("all", { prefix: "DFX_" }),
  ],
  css: {
    postcss: {
      plugins: [autoprefixer(), tailwindcss()],
    }
  },
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  resolve: {
    alias: {
      'ic_vetkeys': path.resolve(__dirname, '../../../frontend/ic_vetkeys/src'),
      'ic_vetkeys/encrypted_maps': path.resolve(__dirname, '../../../frontend/ic_vetkeys/src/encrypted_maps'),
    }
  },
  root: "./",
  server: {
    hmr: false
  }
})