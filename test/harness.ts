export { expect } from 'expect';
import { JestAssertionError } from 'expect';
import { glob } from 'glob';
import path from 'path';

export class Stats {
    total = 0;
    passed = 0;
    failed = 0;
    errors = 0;

    merge(s: Stats) {
        this.total += s.total;
        this.passed += s.passed;
        this.failed += s.failed;
        this.errors += s.errors;
    }
}

export let testDepth = 0;
export let testStats = new Stats();

function indent(msg: string) {
    let str = '';
    for (let i = 0; i < testDepth; i++) str = str + '    ';
    console.log(str + msg);
}

export async function describe(what: string, f: () => (Promise<void> | void)): Promise<void> {
    indent('- ' + what);
    testDepth++;
    await f();
    testDepth--;
}

export async function it(what: string, f: () => (Promise<void> | void)): Promise<void> {
    try {
        testStats.total++;
        await f();
        testStats.passed++;
        indent('✓ ' + what);
    } catch (exn) {
        if (exn instanceof JestAssertionError) {
            testStats.failed++;
            indent('\x1b[33m✗ ' + what + '\x1b[0m')
            console.error(`${'\x1b[31m'}${exn.message}${'\x1b[0m'}`);
        } else {
            testStats.errors++;
            throw exn;
        }
    }
}

export async function runTests(patterns: string[]): Promise<void> {
    for (const pattern of patterns) {
        const files = glob.sync(pattern, { nodir: true });
        for (const mod of files) {
            await describe(mod, async () => {
                await import(path.resolve(process.cwd(), mod));
            });
        }
    }
}

(async () => {
    if (Object.is(require.main, module)) {
        console.time('tests');
        let patterns = process.argv.slice(2);
        if (patterns.length === 0) patterns = ['./lib-test/**/*.test.js'];
        await runTests(patterns);
        console.timeEnd('tests');
        console.log(testStats);
    }
})();
