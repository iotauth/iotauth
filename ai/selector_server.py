#!/usr/bin/env python3
"""
Physical Context Challenge Selector Server powered by Gemma LLM.

Serves an HTTP API endpoint to select optimal physical challenge methods 
based on Auth Server feasible challenge sets, physical context, and security requirements.
"""

import argparse
import json
import logging
import re
import sys
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
import uvicorn
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AISelectorServer")

# ==============================================================================
# System Prompt Definition
# ==============================================================================
SYSTEM_PROMPT = """You are a Physical Context Challenge Selector operating inside an authentication server.

Your task is to select the most appropriate physical challenge method for each required physical check.

You MUST follow these rules:
1. Do not invent new challenge types or methods.
2. Only select methods provided in the candidate methods list.
3. Only select methods that are marked as feasible by the authentication server.
4. Satisfy all required physical checks.
5. Respect the communication policy and its challenge resource constraints.
6. Consider the requester capability, target capability, physical context, and security requirements.
7. For LOCAL checks, only the requester participates.
8. For MUTUAL checks, both requester and target must satisfy the method requirements.
9. Prefer methods that provide stronger physical evidence when multiple methods are feasible.
10. Prefer methods with lower latency, lower privacy cost, and higher reliability when security is equivalent.
11. Do not generate execution parameters such as protocol rounds, timing values, nonces, or sensor thresholds unless they are explicitly provided in the candidate method definition.
12. Return only the requested JSON output.

Your role is to decide:
Which feasible physical challenge method should be used to satisfy each required check?

The authentication server will generate the actual challenge after your decision."""

# ==============================================================================
# Method Property Knowledge Base (Defaults for Candidate Methods)
# ==============================================================================
DEFAULT_METHOD_PROPERTIES = {
    "IR": {
        "security": "HIGH",
        "reliability": "HIGH",
        "latency": "LOW",
        "privacyCost": "LOW"
    },
    "ULTRASOUND": {
        "security": "HIGH",
        "reliability": "MEDIUM",
        "latency": "MEDIUM",
        "privacyCost": "LOW"
    },
    "CAMERA": {
        "security": "MEDIUM",
        "reliability": "HIGH",
        "latency": "MEDIUM",
        "privacyCost": "HIGH"
    },
    "THERMAL_CAMERA": {
        "security": "HIGH",
        "reliability": "HIGH",
        "latency": "MEDIUM",
        "privacyCost": "HIGH"
    },
    "THERMOMETER": {
        "security": "MEDIUM",
        "reliability": "HIGH",
        "latency": "LOW",
        "privacyCost": "LOW"
    }
}


def build_candidate_methods(feasible_challenges: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Transforms Auth Server feasibleChallenges object into LLM candidateMethods list."""
    candidates = []
    for check_id, check_data in feasible_challenges.items():
        if isinstance(check_data, dict):
            topology = check_data.get("topology", "LOCAL")
            methods = check_data.get("methods", [])
        elif isinstance(check_data, list):
            topology = "MUTUAL" if check_id == "CO_LOCATION" else "LOCAL"
            methods = check_data
        else:
            continue

        for m_info in methods:
            if isinstance(m_info, dict):
                m_name = m_info.get("method", "UNKNOWN")
            else:
                m_name = str(m_info)

            props = DEFAULT_METHOD_PROPERTIES.get(m_name, {
                "security": "MEDIUM",
                "reliability": "MEDIUM",
                "latency": "MEDIUM",
                "privacyCost": "MEDIUM"
            })

            candidates.append({
                "check": check_id,
                "method": m_name,
                "topology": topology,
                "feasible": True,
                "properties": props
            })
    return candidates


def adapt_auth_server_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adapts incoming Auth Server Step 1 JSON payload into the exact prompt input format.
    """
    requester = raw_payload.get("requester", "net1.robot1")
    target = raw_payload.get("target", "net1.box1")
    req_checks_raw = raw_payload.get("requiredChecks", [])
    feasible_challenges = raw_payload.get("feasibleChallenges", {})
    eff_caps = raw_payload.get("effectiveCapabilities", {})

    # Build requiredChecks array of objects
    required_checks = []
    for check_item in req_checks_raw:
        if isinstance(check_item, dict):
            required_checks.append(check_item)
        else:
            check_id = str(check_item)
            topology = "MUTUAL" if check_id == "CO_LOCATION" else "LOCAL"
            if check_id in feasible_challenges and isinstance(feasible_challenges[check_id], dict):
                topology = feasible_challenges[check_id].get("topology", topology)
            required_checks.append({
                "id": check_id,
                "topology": topology
            })

    # Build capabilities
    requester_caps = eff_caps.get("requester", {"sensors": [], "actuators": []})
    target_caps = eff_caps.get("target", {"sensors": [], "actuators": []})

    # Build candidate methods
    candidates = build_candidate_methods(feasible_challenges)

    # Physical context & security requirements defaults if not specified
    physical_context = raw_payload.get("physicalContext", {
        "lighting": "NORMAL",
        "noiseLevel": "LOW",
        "temperatureCelsius": 22,
        "humanCount": 1
    })
    security_reqs = raw_payload.get("securityRequirements", {
        "minimumSecurity": "HIGH",
        "requireFreshness": True
    })

    return {
        "request": {
            "requester": requester,
            "target": target
        },
        "requiredChecks": required_checks,
        "requesterCapabilities": requester_caps,
        "targetCapabilities": target_caps,
        "candidateMethods": candidates,
        "policy": {
            "allowedSensors": requester_caps.get("sensors", []),
            "allowedActuators": requester_caps.get("actuators", [])
        },
        "physicalContext": physical_context,
        "securityRequirements": security_reqs
    }


# ==============================================================================
# Model Loading & Inference Pipeline
# ==============================================================================
class LLMInferenceEngine:
    def __init__(self, model_name: str, device: str = "cuda", use_mock: bool = False):
        self.use_mock = use_mock
        self.model_name = model_name
        self.device = device

        if not use_mock:
            logger.info(f"Loading Gemma model: {model_name} on {device}...")
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM

            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if "cuda" in device else torch.float32,
                device_map="auto" if "cuda" in device else None
            )
            logger.info("Gemma model loaded successfully!")

    def generate(self, adapted_input: Dict[str, Any]) -> Dict[str, Any]:
        if self.use_mock:
            logger.info("[Mock Mode] Generating mock response...")
            selected = []
            for check_obj in adapted_input["requiredChecks"]:
                check_id = check_obj["id"]
                candidates = [c for c in adapted_input["candidateMethods"] if c["check"] == check_id and c["feasible"]]
                if candidates:
                    chosen = candidates[0]
                    selected.append({
                        "check": check_id,
                        "method": chosen["method"],
                        "reason": f"{chosen['method']} is feasible and satisfies security requirements.",
                        "confidence": 0.98
                    })
                else:
                    selected.append({
                        "check": check_id,
                        "method": None,
                        "reason": "No feasible challenge method is available for this required check.",
                        "confidence": 1.0
                    })
            return {"selectedChallenges": selected}

        import torch

        user_content = json.dumps(adapted_input, indent=2)
        prompt = f"<bos><start_of_turn>system\n{SYSTEM_PROMPT}<end_of_turn>\n<start_of_turn>user\nInput:\n{user_content}\n\nReturn JSON output only:<end_of_turn>\n<start_of_turn>model\n"

        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.1,
                top_p=0.9,
                do_sample=False
            )

        response_text = self.tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
        logger.info(f"Raw Model Response:\n{response_text}")

        return self.parse_json_response(response_text, adapted_input)

    def parse_json_response(self, text: str, adapted_input: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts and parses JSON object from model output."""
        try:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except Exception as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")

        # Fallback response if LLM formatting failed
        logger.warning("Using safe fallback selector logic...")
        selected = []
        for check_obj in adapted_input["requiredChecks"]:
            check_id = check_obj["id"]
            candidates = [c for c in adapted_input["candidateMethods"] if c["check"] == check_id and c["feasible"]]
            if candidates:
                chosen = candidates[0]
                selected.append({
                    "check": check_id,
                    "method": chosen["method"],
                    "reason": f"Selected feasible method {chosen['method']}.",
                    "confidence": 0.95
                })
            else:
                selected.append({
                    "check": check_id,
                    "method": None,
                    "reason": "No feasible challenge method is available for this required check.",
                    "confidence": 1.0
                })
        return {"selectedChallenges": selected}


# ==============================================================================
# FastAPI Server Initialization
# ==============================================================================
app = FastAPI(title="Physical Context Challenge Selector Server")
engine: Optional[LLMInferenceEngine] = None


@app.post("/select_challenge")
def select_challenge(payload: Dict[str, Any]):
    if engine is None:
        raise HTTPException(status_code=500, detail="Inference engine not initialized")

    logger.info(f"Received request payload for requester: {payload.get('requester', 'unknown')}")
    adapted_input = adapt_auth_server_payload(payload)
    result = engine.generate(adapted_input)
    logger.info(f"Selection Result: {json.dumps(result, indent=2)}")
    return result


@app.get("/health")
def health_check():
    return {"status": "ok", "model": engine.model_name if engine else "none", "mock": engine.use_mock if engine else False}


def main():
    parser = argparse.ArgumentParser(description="Gemma Physical Context Challenge Selector Server")
    parser.add_argument("--model", type=str, default="google/gemma-2-2b-it", help="HuggingFace Gemma model checkpoint")
    parser.add_argument("--port", type=int, default=8000, help="Server port number")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Server host IP")
    parser.add_argument("--device", type=str, default="cuda", help="Inference device (cuda / cpu)")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode without loading GPU model")

    args = parser.parse_args()

    global engine
    engine = LLMInferenceEngine(model_name=args.model, device=args.device, use_mock=args.mock)

    logger.info(f"Starting Challenge Selector API server on {args.host}:{args.port}...")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
