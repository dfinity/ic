import svelte from "rollup-plugin-svelte";
import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import livereload from "rollup-plugin-livereload";
import terser from "@rollup/plugin-terser";
import sveltePreprocess from "svelte-preprocess";
import typescript from "@rollup/plugin-typescript";
import css from "rollup-plugin-css-only";
import json from "@rollup/plugin-json";
import injectProcessEnv from "rollup-plugin-inject-process-env";

const production = !process.env.ROLLUP_WATCH;

function serve(exposeHost) {
  let server;

  function toExit() {
    if (server) server.kill(0);
  }

  return {
    writeBundle() {
      if (server) return;
      server = require("child_process").spawn(
        "npm",
        exposeHost
          ? ["run", "start-expose", "--", "--dev"]
          : ["run", "start", "--", "--dev"],
        {
          stdio: ["ignore", "inherit", "inherit"],
          shell: true,
        }
      );

      process.on("SIGTERM", toExit);
      process.on("exit", toExit);
    },
  };
}

export default (config) => {
  const exposeHost = !!config.configExpose;

  return {
    input: "src/main.ts",
    output: {
      sourcemap: true,
      name: "app",
      format: "iife",

      file: "public/build/main.js",
      inlineDynamicImports: true,
    },
    plugins: [
      svelte({
        preprocess: sveltePreprocess({
          sourceMap: !production,
          postcss: {
            plugins: [require("tailwindcss")(), require("autoprefixer")()],
          },
        }),
        compilerOptions: {
          // enable run-time checks when not in production
          dev: !production,
        },
      }),
      // we'll extract any component CSS out into
      // a separate file - better for performance
      css({ output: "bundle.css" }),

      // If you have external dependencies installed from
      // npm, you'll most likely need these plugins. In
      // some cases you'll need additional configuration -
      // consult the documentation for details:
      // https://github.com/rollup/plugins/tree/master/packages/commonjs
      resolve({
        preferBuiltins: false,
        browser: true,
        dedupe: ["svelte"],
      }),
      commonjs(),
      typescript({
        sourceMap: !production,
        inlineSources: !production,
      }),
      json(),
      injectProcessEnv({
        DFX_NETWORK: process.env.DFX_NETWORK,
        CANISTER_ID_ENCRYPTED_NOTES: process.env.CANISTER_ID_ENCRYPTED_NOTES,
      }),

      // In dev mode, call `npm run start` once
      // the bundle has been generated
      !production && serve(exposeHost),

      // Watch the `public` directory and refresh the
      // browser on changes when not in production
      !production && livereload("public"),

      // If we're building for production (npm run build
      // instead of npm run dev), minify
      production && terser(),
    ],
    watch: {
      clearScreen: false,
    },
    onwarn: function (warning) {
      if (
        [
          "CIRCULAR_DEPENDENCY",
          "THIS_IS_UNDEFINED",
          "EVAL",
          "NAMESPACE_CONFLIC",
        ].includes(warning.code)
      ) {
        return;
      }
      console.warn(warning.message);
    },
  };
};
