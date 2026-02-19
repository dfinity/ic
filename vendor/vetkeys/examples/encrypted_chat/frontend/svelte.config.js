import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import adapter from '@sveltejs/adapter-static';

const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			pages: 'dist',
			assets: 'dist',
			fallback: null,
			precompress: true
		}),
		prerender: {
			entries: ['*'] // ensures all routes are prerendered
		},
		output: {
			bundleStrategy: 'single'
		},
		env: {
			publicPrefix: ''
		}
	},
	compilerOptions: {
		experimental: {
			async: true
		}
	}
};
export default config;
