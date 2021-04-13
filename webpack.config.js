const path = require('path');

module.exports = {
  entry: './lib/SecureStorage.js',
  output: {
    filename: 'SecureStorage.min.js',
    path: path.resolve(__dirname, 'dist'),
  },
  mode: 'production',
  devtool: 'source-map'
}