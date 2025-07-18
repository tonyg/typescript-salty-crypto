import { defineConfig } from 'tsup';

export default defineConfig({
    entry: {
        'salty-crypto': 'src/index.ts',
    },
    format: ['cjs', 'esm', 'iife'],
    outExtension({ format }) {
        switch (format) {
            case 'cjs': return { js: '.cjs' };
            case 'esm': return { js: '.mjs' };
            case 'iife': return { js: '.js' };
        }
    },
    globalName: 'SaltyCrypto',
    dts: true,
    sourcemap: true,
    clean: true,
    minify: true,
    target: 'es2017',
});
