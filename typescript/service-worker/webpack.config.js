const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require('webpack');

module.exports = {
  entry: {
    'install-script': path.join(__dirname, 'src/index.ts'),
    sw: path.join(__dirname, 'src/sw/sw.ts'),
  },
  mode: 'production',
  target: 'web',
  devtool: 'source-map',
  output: {
    path: path.join(__dirname, 'dist'),
    filename: '[name].js',
    publicPath: '/',
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'ts-loader',
          },
        ],
      },
    ],
  },
  resolve: {
    alias: {
      process: 'process/browser',
    },
    extensions: ['.tsx', '.ts', '.js'],
    fallback: {
      assert: require.resolve('assert/'),
      events: require.resolve('events/'),
      stream: require.resolve('stream-browserify/'),
      util: require.resolve('util/'),
    },
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: 'src/index.html',
      filename: 'index.html',
      chunks: ['install-script'],
    }),
    new webpack.ProvidePlugin({
      process: require.resolve('process/browser'),
    }),
    new webpack.EnvironmentPlugin({
      FORCE_FETCH_ROOT_KEY: false,
    }),
  ],
};
