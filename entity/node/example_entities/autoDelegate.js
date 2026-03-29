"use strict";

const SecureCommClient = require("../accessors/SecureCommClient");
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function privilegeHandler(privilege) {
    if (privilege != null) {
        console.log("Handler: privilege request completed");
        console.log("Privilege result:", privilege);
    } else {
        console.log("Handler: delegation is not performed.");
    }
}

function errorHandler(error) {
    console.log("Handler error:", error);
}

async function runPrivilegeTest(nodeConfig, type, subject, object, validity, timeoutMs = 10000) {
    const client = new SecureCommClient(nodeConfig);
    client.initialize();

    client.setOutputHandler("privilege", privilegeHandler);
    client.setOutputHandler("error", errorHandler);

    let lastError = null;

    console.log(
        `Privilege request: ${nodeConfig} | type=${type}, subject=${subject}, object=${object}, validity=${validity}`
    );

    const startNs = process.hrtime.bigint();

    client.performPrivilege(type, subject, object, validity);

    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        const privilege = client.latestOutput("privilege");
        const error = client.latestOutput("error");

        if (error && error !== lastError) {
            lastError = error;
            console.log(`[DEBUG error] ${nodeConfig} | ${error}`);
            return {
                nodeConfig,
                type,
                subject,
                object,
                validity,
                success: false,
                latencyMs: Number(process.hrtime.bigint() - startNs) / 1e6,
                reason: error,
            };
        }

        if (privilege != null) {
            const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;

            console.log(
                `[PASS] ${nodeConfig} | ${subject} -> ${object} | ${latencyMs.toFixed(3)} ms`
            );

            return {
                nodeConfig,
                type,
                subject,
                object,
                validity,
                success: true,
                latencyMs,
                reason: "privilege completed",
                privilege,
            };
        }

        await sleep(100);
    }

    return {
        nodeConfig,
        type,
        subject,
        object,
        validity,
        success: false,
        latencyMs: null,
        reason: lastError || "timeout",
    };
}

async function main() {
    const tests = [
        ["configs/net1/node0.config", "DelegationGrant", "Node1", "ResourceA", "1*day"],
        ["configs/net1/node0.config", "DelegationGrant", "Node1", "ResourceB", "1*day"],
        ["configs/net1/node0.config", "DelegationGrant", "Node2", "ResourceC", "1*day"],
        ["configs/net1/node0.config", "DelegationGrant", "Node2", "ResourceD", "1*day"],
        ["configs/net1/node1.config", "DelegationGrant", "Node3", "ResourceA", "1*day"],
        ["configs/net1/node1.config", "DelegationGrant", "Node4", "ResourceB", "1*day"],
        ["configs/net1/node2.config", "DelegationGrant", "Node5", "ResourceC", "1*day"],
        ["configs/net1/node2.config", "DelegationGrant", "Node6", "ResourceD", "1*day"],
    ];

    const results = [];
    const startAll = process.hrtime.bigint();

    for (const [nodeConfig, type, subject, object, validity] of tests) {
        results.push(
            await runPrivilegeTest(nodeConfig, type, subject, object, validity)
        );
    }

    const totalElapsedMs = Number(process.hrtime.bigint() - startAll) / 1e6;

    const success = results.filter(r => r.success);
    const fail = results.filter(r => !r.success);

    const totalLatency = success.reduce((sum, r) => sum + (r.latencyMs || 0), 0);
    const avgLatency = success.length ? totalLatency / success.length : 0;
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