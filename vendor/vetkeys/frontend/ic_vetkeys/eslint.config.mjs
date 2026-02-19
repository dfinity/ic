// @ts-check

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default tseslint.config(
    eslint.configs.recommended,
    tseslint.configs.recommendedTypeChecked,
    eslintPluginPrettierRecommended,
    {
      languageOptions: {
        parserOptions: {
          project: path.resolve(__dirname, "tsconfig.tests.json"),
          tsconfigRootDir: __dirname,
        },
      },
      rules: {
        '@typescript-eslint/naming-convention': [
          'error',
          {
            selector: 'variableLike',
            format: ['camelCase'],
          },
          {
            selector: 'variable',
            modifiers: ['const'],
            format: ['camelCase', 'UPPER_CASE'],
          },
          {
            selector: 'typeLike',
            format: ['PascalCase'],
          },
        ],
      },
    },
    {
        ignores: [
            "dist/",
            "src/declarations",
            "coverage/",
            "*.config.js",
            "*.config.cjs",
            "*.config.mjs",
            "*.config.ts",
        ],
    },
);
