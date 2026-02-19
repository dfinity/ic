// @ts-check

import eslint from "@eslint/js";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import globals from "globals";
import tseslint from "typescript-eslint";
import svelteConfig from "./svelte.config.js";
import svelte from "eslint-plugin-svelte";

export default tseslint.config(
    eslint.configs.recommended,
    tseslint.configs.recommendedTypeChecked,
    ...svelte.configs.recommended,
    eslintPluginPrettierRecommended,
    {
        languageOptions: {
            parserOptions: {
                projectService: {
                    defaultProject: "./tsconfig.json",
                },
                tsconfigRootDir: import.meta.dirname,
            },
            globals: {
                ...globals.browser,
                ...globals.es2020,
            },
        },
    },
    {
        files: ["**/*.svelte", "**/*.svelte.ts", "**/*.svelte.js"],
        languageOptions: {
            parserOptions: {
                projectService: true,
                extraFileExtensions: [".svelte"],
                parser: tseslint.parser,
                svelteConfig,
            },
        },
    },
    {
        ignores: [
            "dist/",
            "src/declarations",
            "*.config.js",
            "*.config.cjs",
            "*.config.mjs",
            "*.config.ts",
        ],
    },
    {
        rules: {
            "@typescript-eslint/no-unsafe-argument": "off",
            "@typescript-eslint/no-unsafe-member-access": "off",
        },
    },
);
