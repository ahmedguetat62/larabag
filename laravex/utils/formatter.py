import json
import os
from typing import Dict, Any, List
from tabulate import tabulate
from colorama import Fore, Style
from laravex.utils.output import print_output

def get_status_color(status: str) -> str:
    """Returns the color code for a given status."""
    status = status.upper()
    if status in ["CONFIRMED", "VULNERABLE"]:
        return Fore.RED
    elif status in ["FOUND"]:
        return Fore.YELLOW
    elif status in ["SAFE", "UNKNOWN"]:
        return Fore.GREEN
    else:
        return Style.RESET_ALL

def format_results(all_results: Dict[str, Any]):
    """
    Formats and prints the aggregated scan results in a human-readable summary
    and exports to JSON if the LARAVEX_JSON_OUTPUT environment variable is set.
    """
    # --- JSON EXPORT ---
    json_output_env = os.getenv("LARAVEX_JSON_OUTPUT")
    if json_output_env:
        try:
            with open(json_output_env, 'w') as f:
                json.dump(all_results, f, indent=4)
            print_output.success(f"Scan results successfully exported to JSON: {json_output_env}")
        except Exception as e:
            print_output.error(f"Failed to export JSON results: {e}")

    # --- TERMINAL OUTPUT ---
    print(f"\n{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'LARAVEX SCAN SUMMARY':^80}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}\n")

    all_findings: List[Dict[str, str]] = []

    # 1. Vulnerability Lookup Results
    vulnerability_results = all_results.get("vulnerability_lookup", {})
    vulnerability_findings = []
    if vulnerability_results:
        for key, data in vulnerability_results.items():
            finding = {
                "Module": "Vulnerability Lookup",
                "Check": key,
                "Status": data.get("status", "N/A"),
                "Severity": data.get("severity", "HIGH"),
                "Details": data.get("value", "N/A")
            }
            all_findings.append(finding)
            if data.get("status") == "FOUND":
                vulnerability_findings.append(finding)

    if vulnerability_findings:
        print(f"\n{Fore.RED}!!! CRITICAL VULNERABILITY LOOKUP RESULTS ({len(vulnerability_findings)}) !!!{Style.RESET_ALL}")
        table_data = []
        for f in vulnerability_findings:
            status_colored = f"{get_status_color(f['Status'])}{f['Status']}{Style.RESET_ALL}"
            severity_colored = f"{Fore.RED}{f['Severity']}{Style.RESET_ALL}"
            table_data.append([f['Check'], status_colored, severity_colored, f['Details']])
        headers = ["Check", "Status", "Severity", "Exploit Details"]
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid", maxcolwidths=[None, None, None, 100]))

    # 2. Fingerprint Results
    fingerprint_results = all_results.get("fingerprint", {})
    for key, data in fingerprint_results.items():
        all_findings.append({
            "Module": "Fingerprint",
            "Check": key,
            "Status": data.get("status", "N/A"),
            "Severity": "INFO",
            "Details": data.get("value", "N/A")
        })

    # 3. Core Security Checks
    core_checks_results = all_results.get("core_checks", {})
    for key, data in core_checks_results.items():
        all_findings.append({
            "Module": "Core Checks",
            "Check": key,
            "Status": data.get("status", "N/A"),
            "Severity": data.get("severity", "LOW"),
            "Details": data.get("value", "N/A")
        })

    # 4. RCE Scanner Results
    rce_results = all_results.get("rce_scanner", {})
    for key, data in rce_results.items():
        all_findings.append({
            "Module": "RCE Scanner",
            "Check": key,
            "Status": data.get("status", "N/A"),
            "Severity": data.get("severity", "CRITICAL"),
            "Details": data.get("value", "N/A")
        })

    # 5. Enumeration Results
    enumeration_results = all_results.get("enumeration", {})
    for key, data in enumeration_results.items():
        all_findings.append({
            "Module": "Enumeration",
            "Check": key,
            "Status": data.get("status", "N/A"),
            "Severity": data.get("severity", "INFO"),
            "Details": data.get("value", "N/A")
        })

    # Summary Table for Critical Findings
    vulnerable_findings = [
        f for f in all_findings 
        if f["Status"].upper() in ["VULNERABLE", "CONFIRMED", "FOUND"] and f["Module"] != "Vulnerability Lookup"
    ]
    
    if vulnerable_findings:
        print(f"\n{Fore.RED}!!! CORE SECURITY & FINGERPRINT FINDINGS ({len(vulnerable_findings)}) !!!{Style.RESET_ALL}")
        table_data = []
        for f in vulnerable_findings:
            status_colored = f"{get_status_color(f['Status'])}{f['Status']}{Style.RESET_ALL}"
            severity_colored = f"{Fore.RED}{f['Severity']}{Style.RESET_ALL}" if f['Severity'].upper() in ['CRITICAL', 'HIGH'] else f['Severity']
            table_data.append([f['Module'], f['Check'], status_colored, severity_colored, f['Details']])
        headers = ["Module", "Check", "Status", "Severity", "Details"]
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid", maxcolwidths=[None, None, None, None, 80]))
    else:
        print(f"\n{Fore.GREEN}No critical vulnerabilities or confirmed exposures found in core checks.{Style.RESET_ALL}")

    print(f"\n{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
