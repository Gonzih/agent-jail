#!/usr/bin/env node
/**
 * Network operations test script for agent-jail integration testing.
 * Makes HTTP requests to verify network event capture.
 */
const https = require('https');
const dns = require('dns');

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

function resolveDns(hostname) {
    return new Promise((resolve, reject) => {
        dns.lookup(hostname, (err, address) => {
            if (err) reject(err);
            else resolve(address);
        });
    });
}

async function main() {
    console.log("=== Node.js Network Test ===");

    // Test URLs
    const urls = [
        "https://httpbin.org/ip",
        "https://httpbin.org/headers",
        "https://api.github.com/zen",
    ];

    for (const url of urls) {
        console.log(`\nFetching: ${url}`);
        try {
            const { status, body } = await fetch(url);
            console.log(`  Status: ${status}`);
            console.log(`  Body preview: ${body.slice(0, 100)}...`);
        } catch (err) {
            console.log(`  Error: ${err.message}`);
        }
    }

    // DNS resolution test
    const hosts = ["google.com", "github.com", "api.anthropic.com"];
    console.log("\n--- DNS Resolution ---");
    for (const host of hosts) {
        try {
            const ip = await resolveDns(host);
            console.log(`  ${host} -> ${ip}`);
        } catch (err) {
            console.log(`  ${host} -> ERROR: ${err.message}`);
        }
    }

    console.log("\n=== Network Test Complete ===");
    return 0;
}

main().then(process.exit).catch(err => {
    console.error(err);
    process.exit(1);
});
