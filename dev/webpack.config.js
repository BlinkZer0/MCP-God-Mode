const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');

module.exports = {
  mode: 'production',
  entry: './dist/server-minimal.js',
  target: 'node',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'server-webpack.js',
    libraryTarget: 'commonjs2'
  },
  externals: {
    // Keep these as external dependencies
    '@modelcontextprotocol/sdk': 'commonjs @modelcontextprotocol/sdk',
    'simple-git': 'commonjs simple-git',
    'mathjs': 'commonjs mathjs',
    'nanoid': 'commonjs nanoid',
    'zod': 'commonjs zod'
  },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          compress: {
            drop_console: true,
            drop_debugger: true,
            pure_funcs: ['console.log', 'console.info', 'console.debug']
          },
          mangle: {
            keep_fnames: false
          }
        }
      })
    ],
    usedExports: true,
    sideEffects: false
  },
  resolve: {
    extensions: ['.js', '.ts']
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      }
    ]
  },
  stats: {
    chunks: false,
    modules: false,
    assets: true,
    timings: true
  }
};
