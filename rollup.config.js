module.exports = {
  input: 'lib/src/index.js',
  plugins: [require('@rollup/plugin-terser')()],
  output: {
    file: 'dist/index.js',
    format: 'umd',
    name: 'SaltyCrypto',
  },
};
