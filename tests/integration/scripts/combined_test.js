#!/usr/bin/env node
/**
 * Combined test script that exercises filesystem, network, and process operations.
 * This simulates a realistic agent workload.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const { execSync, spawn } = require('child_process');

function fetch(url) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout: 10000 }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, body: data }));
        });
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
    });
}

async function main() {
    console.log("=== Combined Agent Simulation (Node.js) ===");
    console.log(`PID: ${process.pid}`);
    const startTime = Date.now();

    // Phase 1: Set up working directory
    console.log("\n[Phase 1] Setting up workspace...");
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'agent_workspace_node_'));
    console.log(`  Workspace: ${workspace}`);

    // Phase 2: Download some data (network)
    console.log("\n[Phase 2] Fetching external data...");
    let data;
    try {
        const { body } = await fetch("https://httpbin.org/json");
        data = JSON.parse(body);
        console.log(`  Fetched JSON with ${Object.keys(data).length} keys`);
    } catch (err) {
        console.log(`  Network fetch failed: ${err.message}`);
        data = { fallback: true, reason: err.message };
    }

    // Phase 3: Write data to file (filesystem)
    console.log("\n[Phase 3] Saving data to disk...");
    const dataFile = path.join(workspace, 'fetched_data.json');
    fs.writeFileSync(dataFile, JSON.stringify(data, null, 2));
    console.log(`  Saved to: ${dataFile}`);

    // Phase 4: Process data with subprocess (process)
    console.log("\n[Phase 4] Processing data...");
    const wcOutput = execSync(`wc -c "${dataFile}"`, { encoding: 'utf-8' });
    const byteCount = wcOutput.trim().split(/\s+/)[0];
    console.log(`  File size: ${byteCount} bytes`);

    // Phase 5: Create analysis output
    console.log("\n[Phase 5] Generating analysis...");
    const analysis = {
        timestamp: Date.now(),
        workspace: workspace,
        data_file: dataFile,
        file_size_bytes: parseInt(byteCount),
        network_success: !data.fallback,
        duration_ms: Date.now() - startTime
    };
    const analysisFile = path.join(workspace, 'analysis.json');
    fs.writeFileSync(analysisFile, JSON.stringify(analysis, null, 2));
    console.log(`  Analysis saved to: ${analysisFile}`);

    // Phase 6: Run a subprocess that does its own file I/O
    console.log("\n[Phase 6] Running nested subprocess...");
    const nestedOutput = path.join(workspace, 'nested_output.txt');
    const script = `
        const fs = require('fs');
        const data = JSON.parse(fs.readFileSync('${analysisFile}'));
        console.log('Nested process read ' + Object.keys(data).length + ' analysis fields');
        fs.writeFileSync('${nestedOutput}', 'Output from nested process\\n');
    `;
    const result = execSync(`node -e "${script.replace(/"/g, '\\"')}"`, { encoding: 'utf-8' });
    console.log(`  ${result.trim()}`);

    if (fs.existsSync(nestedOutput)) {
        console.log(`  Nested output file created: ${nestedOutput}`);
    }

    // Phase 7: Cleanup
    console.log("\n[Phase 7] Cleanup...");
    for (const f of fs.readdirSync(workspace)) {
        fs.unlinkSync(path.join(workspace, f));
    }
    fs.rmdirSync(workspace);
    console.log(`  Removed workspace: ${workspace}`);

    const totalTime = Date.now() - startTime;
    console.log(`\n=== Combined Test Complete (${totalTime}ms) ===`);
    return 0;
}

main().then(process.exit).catch(err => {
    console.error(err);
    process.exit(1);
});
