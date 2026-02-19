import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import environment from 'vite-plugin-environment';
import typescript from '@rollup/plugin-typescript';

export default defineConfig({
	plugins: [
		typescript(),
		tailwindcss(),
		sveltekit(),
		environment('all', { prefix: 'CANISTER_' }),
		environment('all', { prefix: 'DFX_' })
	],
	server: {
		proxy: {
			'/api': {
				target: 'http://localhost:4943',
				changeOrigin: true
			}
		}
	},
	build: {
		sourcemap: true,
	}
});
