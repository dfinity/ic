import path from 'path';
import HtmlWebpackPlugin from 'html-webpack-plugin';
import webpack, { Configuration } from 'webpack';
import packageJson from './package.json';
import CopyPlugin from 'copy-webpack-plugin';

const webpackConfig = (env: NodeJS.ProcessEnv): Configuration => {
  const isDevelopment = Boolean(env.development);
  const outputPath = path.join(
    __dirname,
    isDevelopment ? 'dist-dev' : 'dist-prod'
  );

  return {
    entry: {
      'install-script': path.join(__dirname, 'src/index.ts'),
      sw: path.join(__dirname, 'src/sw/sw.ts'),
    },
    mode: isDevelopment ? 'development' : 'production',
    target: 'webworker',
    devtool: 'source-map',
    output: {
      path: outputPath,
      filename: '[name].js',
      publicPath: '/',
      assetModuleFilename: (pathData) =>
        pathData.filename?.endsWith('.wasm')
          ? '[name].wasm'
          : '[hash][ext][query]',
    },
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          exclude: /node_modules/,
          use: [
            { loader: 'minify-html-literals-loader' },
            { loader: 'ts-loader' },
          ],
        },
        {
          test: /\.wasm$/,
          type: 'asset/inline',
        },
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
      alias: {
        'lit-html/lib/shady-render.js': path.resolve(
          __dirname,
          './node_modules/lit-html/lit-html.js'
        ),
      },
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: 'src/assets/index.html',
        filename: 'index.html',
        inject: 'body',
        chunks: ['install-script'],
        minify: isDevelopment
          ? false
          : {
              collapseWhitespace: true,
              keepClosingSlash: true,
              removeComments: true,
              removeRedundantAttributes: true,
              removeScriptTypeAttributes: true,
              removeStyleLinkTypeAttributes: true,
              useShortDoctype: true,
              collapseBooleanAttributes: true,
              minifyCSS: true,
            },
      }),
      new CopyPlugin({
        patterns: [
          {
            from: path.join(__dirname, 'src', 'assets'),
            filter: (resourcePath) => {
              return !resourcePath.endsWith('.html');
            },
          },
        ],
      }),
      new webpack.EnvironmentPlugin({
        FORCE_FETCH_ROOT_KEY: isDevelopment,
        VERSION: packageJson.version,
      }),
    ],
  };
};

export default webpackConfig;
