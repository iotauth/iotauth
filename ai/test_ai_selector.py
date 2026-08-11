#!/usr/bin/env python3
"""
Test client for Physical Context Challenge Selector Server.
Sends Step 1 Feasible Challenge Set output to AI Selector API endpoint.
"""

import json
import urllib.request
import sys

SERVER_URL = "http://localhost:8000/select_challenge"

# Sample Feasible Challenge Set JSON from Step 1 Auth Server output
SAMPLE_STEP1_PAYLOAD = {
    "requester": "net1.robot1",
    "target": "net1.box1",
    "effectiveCapabilities": {
        "requester": {
            "sensors": ["LiFi", "IR", "BLE", "CAMERA", "THERMOMETER"],
            "actuators": ["IR", "UltraSound", "BLE", "CAMERA", "THERMOMETER"]
        },
        "target": {
            "sensors": ["LiFi", "IR", "UltraSound", "BLE", "CAMERA", "THERMOMETER"],
            "actuators": ["LiFi", "IR", "UltraSound", "BLE", "CAMERA", "THERMOMETER"]
        }
    },
    "requiredChecks": [
        "HUMAN_PRESENCE",
        "CO_LOCATION",
        "TEMPERATURE_CHECK"
    ],
    "feasibleChallenges": {
        "HUMAN_PRESENCE": {
            "topology": "LOCAL",
            "methods": [
                {"method": "CAMERA", "parameters": {"max_human": 1}}
            ]
        },
        "CO_LOCATION": {
            "topology": "MUTUAL",
            "methods": [
                {"method": "IR", "parameters": {"rounds": 128, "max_delay_us": 1000}},
                {"method": "ULTRASOUND", "parameters": {"rounds": 64, "max_delay_us": 2000}}
            ]
        },
        "TEMPERATURE_CHECK": {
            "topology": "LOCAL",
            "methods": [
                {"method": "THERMOMETER", "parameters": {"min_temperature_celsius": 18}}
            ]
        }
    }
}


def test_ai_selector():
    print("======================================================================")
    print(" Sending Step 1 Feasible Challenge Set to AI Selector Server...")
    print("======================================================================")
    print(json.dumps(SAMPLE_STEP1_PAYLOAD, indent=2))
    print("\n----------------------------------------------------------------------")

    req_data = json.dumps(SAMPLE_STEP1_PAYLOAD).encode("utf-8")
    req = urllib.request.Request(
        SERVER_URL,
        data=req_data,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode("utf-8")
            result = json.loads(res_body)

            print(" Received Selected Challenges Response from AI Server:")
            print("----------------------------------------------------------------------")
            print(json.dumps(result, indent=2))
            print("======================================================================")
            print(" TEST SUCCESSFUL!")
            print("======================================================================")
    except Exception as e:
        print(f"[Error] Failed to communicate with AI Selector Server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    test_ai_selector()
