import { defineConfig } from 'tsup';

export default defineConfig({
    entry: {
        'salty-crypto': 'src/index.ts',
    },
    format: ['cjs', 'esm', 'iife'],
    globalName: 'SaltyCrypto',
    dts: true,
    sourcemap: true,
    clean: true,
    minify: true,
    target: 'es2017',
});
