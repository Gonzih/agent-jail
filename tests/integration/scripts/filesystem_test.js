#!/usr/bin/env node
/**
 * Filesystem operations test script for agent-jail integration testing.
 * Creates, reads, modifies, and deletes files to verify filesystem event capture.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

async function main() {
    console.log("=== Node.js Filesystem Test ===");

    // Create a temp directory
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jail_test_node_'));
    console.log(`Created temp dir: ${testDir}`);

    // Create a file (sync)
    const testFile = path.join(testDir, 'test_file.txt');
    fs.writeFileSync(testFile, 'Hello from Node.js!\n');
    console.log(`Created file: ${testFile}`);

    // Read the file
    const content = fs.readFileSync(testFile, 'utf-8');
    console.log(`Read content: ${content.trim()}`);

    // Append to file
    fs.appendFileSync(testFile, 'Second line\n');
    console.log('Appended to file');

    // Create subdirectory
    const subDir = path.join(testDir, 'subdir');
    fs.mkdirSync(subDir);
    console.log(`Created subdir: ${subDir}`);

    // Create file in subdirectory
    const nestedFile = path.join(subDir, 'nested.json');
    fs.writeFileSync(nestedFile, JSON.stringify({ status: 'success', nested: true }));
    console.log(`Created nested file: ${nestedFile}`);

    // Async file operations
    const asyncFile = path.join(testDir, 'async_test.txt');
    await fs.promises.writeFile(asyncFile, 'Async write!\n');
    console.log(`Created async file: ${asyncFile}`);

    const asyncContent = await fs.promises.readFile(asyncFile, 'utf-8');
    console.log(`Async read: ${asyncContent.trim()}`);

    // List directory
    const files = fs.readdirSync(testDir);
    console.log(`Directory contents: ${JSON.stringify(files)}`);

    // File stats
    const stats = fs.statSync(testFile);
    console.log(`File stats: size=${stats.size}, isFile=${stats.isFile()}`);

    // Delete files
    fs.unlinkSync(nestedFile);
    console.log(`Deleted: ${nestedFile}`);

    fs.rmdirSync(subDir);
    console.log(`Deleted dir: ${subDir}`);

    fs.unlinkSync(asyncFile);
    fs.unlinkSync(testFile);
    console.log(`Deleted test files`);

    fs.rmdirSync(testDir);
    console.log(`Deleted temp dir: ${testDir}`);

    console.log("=== Filesystem Test Complete ===");
    return 0;
}

main().then(process.exit).catch(err => {
    console.error(err);
    process.exit(1);
});
