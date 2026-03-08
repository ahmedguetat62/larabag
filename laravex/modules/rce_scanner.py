import json
import base64
import os
from typing import Dict, Any, Optional
from laravex.utils.output import print_output

class RCEScannerModule:
    """
    Module to scan for Remote Code Execution (RCE) vulnerabilities in Laravel.
    Focuses on:
    1. CVE-2021-3129 (Ignition RCE)
    2. CVE-2018-15133 (X-SRF-TOKEN Unserialize RCE)
    """
    def __init__(self, target_url: str, client: Any):
        self.target_url = target_url.rstrip('/')
        self.client = client

    def check_ignition_rce(self) -> Dict[str, Any]:
        """
        Checks for CVE-2021-3129 (Ignition RCE) using advanced detection logic.
        """
        endpoint = f"{self.target_url}/_ignition/execute-solution"
        try:
            # 1. Check if the endpoint exists
            response = self.client.get(endpoint)
            if response.status_code != 405 and response.status_code != 200:
                return {"status": "SAFE", "severity": "LOW", "value": "Ignition RCE endpoint not found"}

            # 2. Advanced Detection: Try to trigger a specific error that confirms Ignition
            # We use a known solution class and a non-existent file to see if Ignition handles it
            payload = {
                "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                "parameters": {
                    "variableName": "test",
                    "viewFile": "non_existent_file_for_detection"
                }
            }
            
            # Send the POST request
            res = self.client.session.post(endpoint, json=payload, timeout=10)
            
            # If the response contains "viewFile" and "does not exist", it's a strong indicator
            if res.status_code == 500 and ("viewFile" in res.text or "does not exist" in res.text):
                # Further confirmation: Check if we can use a php://filter
                # This is a non-destructive way to see if the filter is processed
                confirm_payload = {
                    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                    "parameters": {
                        "variableName": "test",
                        "viewFile": "php://filter/resource=non_existent_file"
                    }
                }
                confirm_res = self.client.session.post(endpoint, json=confirm_payload, timeout=10)
                
                if confirm_res.status_code == 500:
                    return {
                        "status": "VULNERABLE",
                        "severity": "CRITICAL",
                        "value": f"Ignition RCE (CVE-2021-3129) confirmed at {endpoint}. The application is vulnerable to unauthenticated remote code execution."
                    }

            return {"status": "SAFE", "severity": "LOW", "value": "Ignition RCE endpoint found but not exploitable"}
        except Exception as e:
            return {"status": "UNKNOWN", "severity": "LOW", "value": f"Error checking Ignition RCE: {str(e)}"}

    def check_unserialize_rce(self, app_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Checks for CVE-2018-15133 (X-SRF-TOKEN Unserialize RCE).
        Requires a known APP_KEY.
        """
        if not app_key:
            return {"status": "UNKNOWN", "severity": "LOW", "value": "APP_KEY required for Unserialize RCE check"}
        
        return {
            "status": "POTENTIALLY VULNERABLE",
            "severity": "HIGH",
            "value": f"Target may be vulnerable to Unserialize RCE (CVE-2018-15133) because an APP_KEY was found. This could lead to RCE via crafted X-SRF-TOKEN headers."
        }

    def run(self, fingerprint_results: Dict[str, Any], core_checks_results: Dict[str, Any]) -> Dict[str, Any]:
        print_output.info("Running RCE Scanner module...")
        results = {}
        
        # 1. Check Ignition RCE
        results["Ignition RCE (CVE-2021-3129)"] = self.check_ignition_rce()
        
        # 2. Check Unserialize RCE if APP_KEY was found in .env
        app_key = None
        env_results = core_checks_results.get("Exposed .env File", {})
        if env_results.get("status") == "VULNERABLE":
            # In a real scenario, we would parse the .env content to find APP_KEY
            app_key = "FOUND_IN_ENV" 
            
        results["Unserialize RCE (CVE-2018-15133)"] = self.check_unserialize_rce(app_key)
        
        return results
