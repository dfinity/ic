# ic-vetkd-utils

This package provides utilities for obtaining and decrypting verifiably-encrypted keys via the Internet Computer's [proposed vetKD system API](https://github.com/dfinity/interface-spec/pull/158).

The utilities are intended to be used (1) in an end-user's browser as WebAssembly (Wasm) module via a Javascript wrapper, and (2) for testing the vetKD protocol.

The package is implemented in Rust. To make it usable in Javascript in a browser, the relevant APIs have `wasm-bindgen` annotations so that it can be compiled to Wasm with `wasm-pack`.

## Usage

As the API still needs to stabilize, the package is neither published to [npmjs.org](npmjs.org) nor [crates.io](crates.io) yet. Until then, it is easiest to use the package with `webpack`.

When using [webpack](https://webpack.js.org/) as bundler, which is also used in the default template frontend canister created with the Internet Computer SDK (with `dfx new`), perform the following steps to use the vetKD utils in your application.

1. Ensure you have [wasm-pack installed](https://rustwasm.github.io/wasm-pack/installer/).

2. Run `wasm-pack build --release`

   This will create a `pkg/` folder with various build artifacts including a `.wasm` file and Javascript/Typescript bindings.

3. Run `wasm-pack pack`

   This will create a `ic-vetkd-utils-0.1.0.tgz` file in the `pkg/` folder.

4. Copy the `.tgz` file to your application and add it as dependency in your webpack `package.json` via [its local path](https://docs.npmjs.com/cli/v9/configuring-npm/package-json#local-paths).

   For example, with `"ic-vetkd-utils": "file:path/to/ic-vetkd-utils-0.1.0.tgz"`

6. Run `npm install`

7. Include it from Javascript

   For example, with `import * as vetkd from "ic-vetkd-utils";`

For more details, see, for example, the respective sections in the [wasm-bindgen reference's deployment section](https://rustwasm.github.io/wasm-bindgen/reference/deployment.html) and [the wasm-pack book's build section](https://rustwasm.github.io/wasm-pack/book/commands/build.html).