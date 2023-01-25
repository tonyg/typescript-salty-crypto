module.exports = [
  {
    input: 'lib/index.js',
    plugins: [require('@rollup/plugin-terser')()],
    output: {
      file: 'dist/salty-crypto.js',
      format: 'umd',
      name: 'SaltyCrypto',
    },
  },
  {
    input: 'lib/index.d.ts',
    plugins: [require('rollup-plugin-dts').default()],
    output: {
      file: 'dist/salty-crypto.d.ts',
      format: 'es',
    },
  },
];
