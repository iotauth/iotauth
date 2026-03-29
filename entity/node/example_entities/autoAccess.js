"use strict";

const SecureCommClient = require("../accessors/SecureCommClient");
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function connectedHandler(connected) {
    if (connected == true) {
        console.log('Handler: communication initialization succeeded');
    }
    else {
        console.log('Handler: secure connection with the server closed.');
    }
}

async function runTest(nodeConfig, resourceName, groupName, timeoutMs = 10000) {
    const client = new SecureCommClient(nodeConfig);
    client.initialize();
    client.setOutputHandler('connected', connectedHandler);

    const targetServerInfoList = client.getTargetServerInfoList();
    let lastError = null;

    for (let i = 0; i < targetServerInfoList.length; i++) {
        const commServerInfo = targetServerInfoList[i];

        if (commServerInfo.name != resourceName) continue;

        console.log(`Connecting: ${nodeConfig} -> ${commServerInfo.name} ${commServerInfo.host} ${commServerInfo.port}`);

        const startNs = process.hrtime.bigint();

        client.provideInputResource(
            "serverHostPort",
            { host: commServerInfo.host, port: commServerInfo.port },
            groupName
        );

        const deadline = Date.now() + timeoutMs;

        while (Date.now() < deadline) {
            const connected = client.latestOutput("connected");
            const error = client.latestOutput("error");

            if (error && error !== lastError) {
                lastError = error;

                const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;

                console.log(
                    `[FAIL-ERROR] ${nodeConfig} -> ${commServerInfo.group} | ${latencyMs.toFixed(3)} ms | ${error}`
                );

                client.provideInput("serverHostPort", null);

                return {
                    nodeConfig,
                    resource: groupName,
                    success: false,
                    latencyMs,
                    reason: error,
                };
            }

            if (connected === true) {
                const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;

                console.log(
                    `[PASS] ${nodeConfig} -> ${commServerInfo.group} | ${latencyMs.toFixed(3)} ms`
                );

                client.provideInput("serverHostPort", null);

                return {
                    nodeConfig,
                    resource: groupName,
                    success: true,
                    latencyMs,
                    reason: "connected",
                };
            }

            await sleep(100);
        }

        const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;

        console.log(
            `[FAIL-TIMEOUT] ${nodeConfig} -> ${commServerInfo.group} | ${latencyMs.toFixed(3)} ms`
        );

        client.provideInput("serverHostPort", null);

        return {
            nodeConfig,
            resource: groupName,
            success: false,
            latencyMs,
            reason: lastError || "timeout",
        };
    }

    return {
        nodeConfig,
        resource: resourceName,
        success: false,
        latencyMs: 0,
        reason: "resource not found",
    };
}

async function main() {
    const tests = [
        ["configs/net1/node0.config", "net1.resourceA", "ResourceA"],
        ["configs/net1/node0.config", "net1.resourceB", "ResourceB"],
        ["configs/net1/node0.config", "net1.resourceC", "ResourceC"],
        ["configs/net1/node0.config", "net1.resourceD", "ResourceD"],
        ["configs/net1/node1.config", "net1.resourceA", "ResourceA"],
        ["configs/net1/node1.config", "net1.resourceB", "ResourceB"],
        ["configs/net1/node2.config", "net1.resourceC", "ResourceC"],
        ["configs/net1/node2.config", "net1.resourceD", "ResourceD"],
        ["configs/net1/node3.config", "net1.resourceA", "ResourceA"],
        ["configs/net1/node4.config", "net1.resourceB", "ResourceB"],
        ["configs/net1/node5.config", "net1.resourceC", "ResourceC"],
        ["configs/net1/node6.config", "net1.resourceD", "ResourceD"],
    ];

    const results = [];
    const startAll = process.hrtime.bigint();

    for (const [nodeConfig, resourceName, groupName] of tests) {
        results.push(await runTest(nodeConfig, resourceName, groupName));
    }

    const totalElapsedMs = Number(process.hrtime.bigint() - startAll) / 1e6;

    const success = results.filter(r => r.success);
    const fail = results.filter(r => !r.success);

    const totalLatency = results.reduce((sum, r) => sum + (r.latencyMs || 0), 0);
    const avgLatency = results.length ? totalLatency / results.length : 0;
    const successRate = results.length ? (success.length / results.length) * 100 : 0;

    console.log("\n========== SUMMARY ==========");
    console.log(`Total tests   : ${results.length}`);
    console.log(`Success       : ${success.length}`);
    console.log(`Fail          : ${fail.length}`);
    console.log(`Success rate  : ${successRate.toFixed(2)}%`);
    console.log(`Total latency : ${totalLatency.toFixed(3)} ms`);
    console.log(`Avg latency   : ${avgLatency.toFixed(3)} ms`);
    console.log(`End-to-end    : ${totalElapsedMs.toFixed(3)} ms`);
    console.log("\nDetailed results:");
    console.log(results);
}

main().catch(err => {
    console.error("Fatal error:", err);
    process.exit(1);
});