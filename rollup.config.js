module.exports = {
  input: 'lib/src/index.js',
  plugins: [require('@rollup/plugin-terser')()],
  output: {
    file: 'dist/salty-crypto.js',
    format: 'umd',
    name: 'SaltyCrypto',
  },
};
