import { defineConfig } from 'vite';
import path from 'path';
import dts from 'vite-plugin-dts'

export default defineConfig({
    plugins: [dts({ outDir: 'dist/types' })],
    build: {
        lib: {
            entry: {
                index: path.resolve(__dirname, 'src/index.ts'),
                key_manager: path.resolve(__dirname, 'src/key_manager/index.ts'),
                encrypted_maps: path.resolve(__dirname, 'src/encrypted_maps/index.ts'),
            },
            name: 'ic_vetkeys',
            formats: ['es'],
            fileName: (format, entryName) => `${entryName}.${format}.js`,
        },
        outDir: 'dist/lib',
        emptyOutDir: true
    },
    test: {
        environment: "happy-dom",
        setupFiles: ['test/setup.ts'],
        testTimeout: 120000
    }
});
