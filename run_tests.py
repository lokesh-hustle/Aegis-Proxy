"""
Direct Test Runner for Aegis Proxy.
Executes test functions without requiring external pytest runner.
"""

import sys
import unittest
from test_aegis import (
    test_redaction_utilities,
    test_verify_aegis_token,
    test_proxy_endpoints_integration,
)

if __name__ == "__main__":
    print("=== Running Aegis Proxy Security & Integration Verification ===")
    
    print("[1/3] Testing Secret Redaction Utilities...")
    test_redaction_utilities()
    print("   [PASS] Header & Payload redaction tests passed.")

    print("[2/3] Testing Aegis Token Verification...")
    test_verify_aegis_token()
    print("   [PASS] Aegis Token verification tests passed.")

    print("[3/3] Testing FastAPI Endpoints, Ledger & Anomaly Detection...")
    test_proxy_endpoints_integration()
    print("   [PASS] FastAPI proxy endpoints, budget limits, domain allowlists, ChromaDB vector anomaly detection, and ledger audit passed.")

    print("\n=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY! ===")
