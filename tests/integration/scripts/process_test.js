#!/usr/bin/env node
/**
 * Process operations test script for agent-jail integration testing.
 * Spawns subprocesses to verify process tree event capture.
 */
const { spawn, execSync, exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

async function main() {
    console.log("=== Node.js Process Test ===");
    console.log(`Main PID: ${process.pid}`);
    console.log(`Parent PID: ${process.ppid}`);

    // Spawn a simple subprocess (sync)
    console.log("\n--- execSync: echo ---");
    const output = execSync('echo "Hello from subprocess"', { encoding: 'utf-8' });
    console.log(`  stdout: ${output.trim()}`);

    // Async exec
    console.log("\n--- execAsync: shell command ---");
    const { stdout } = await execAsync('echo $SHELL && pwd');
    console.log(`  stdout: ${stdout.trim()}`);

    // Spawn with event handling
    console.log("\n--- spawn: ls ---");
    await new Promise((resolve) => {
        const ls = spawn('ls', ['-la', '/tmp']);
        let output = '';
        ls.stdout.on('data', data => output += data);
        ls.on('close', code => {
            console.log(`  Exit code: ${code}`);
            console.log(`  Output lines: ${output.trim().split('\n').length}`);
            resolve();
        });
    });

    // Multiple concurrent spawns
    console.log("\n--- Concurrent spawns ---");
    const procs = [];
    for (let i = 0; i < 3; i++) {
        const p = spawn('sleep', ['0.1']);
        console.log(`  Started sleep process ${i}: PID=${p.pid}`);
        procs.push(new Promise(resolve => p.on('close', code => {
            console.log(`  Process ${i} (PID=${p.pid}) exited with code ${code}`);
            resolve();
        })));
    }
    await Promise.all(procs);

    // Environment passing
    console.log("\n--- Environment passing ---");
    const result = await execAsync('echo TEST_VAR=$TEST_VAR', {
        env: { ...process.env, TEST_VAR: 'hello_world' }
    });
    console.log(`  ${result.stdout.trim()}`);

    // Working directory
    console.log("\n--- Working directory ---");
    const pwdResult = await execAsync('pwd', { cwd: '/tmp' });
    console.log(`  pwd in /tmp: ${pwdResult.stdout.trim()}`);

    // Pipe simulation
    console.log("\n--- Process pipe ---");
    const pipe1 = spawn('echo', ['-e', 'line1\\nline2\\nline3']);
    const pipe2 = spawn('wc', ['-l'], { stdio: [pipe1.stdout, 'pipe', 'pipe'] });
    let pipeOutput = '';
    pipe2.stdout.on('data', data => pipeOutput += data);
    await new Promise(resolve => pipe2.on('close', resolve));
    console.log(`  wc -l output: ${pipeOutput.trim()}`);

    console.log("\n=== Process Test Complete ===");
    return 0;
}

main().then(process.exit).catch(err => {
    console.error(err);
    process.exit(1);
});
