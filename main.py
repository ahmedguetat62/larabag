
#!/usr/bin/env python3
import typer
from typing import Optional, Any, Dict
from laravex.utils.output import print_output
from laravex.utils.http_client import http_client, normalize_url
from laravex.modules.fingerprint import FingerprintModule
from laravex.modules.core_checks import CoreChecksModule
from laravex.modules.enumerate import EnumerationModule
from laravex.modules.vulnerability_lookup import VulnerabilityLookupModule
from laravex.modules.rce_scanner import RCEScannerModule
from laravex.utils.formatter import format_results
app = typer.Typer(
    name="laravex",
    help="Laravex - Laravel Penetration Testing Tool",
    add_completion=False
)

@app.command()
def scan(
    target_url: str = typer.Argument(..., help="The target URL of the Laravel application."),
    full: bool = typer.Option(False, "--full", "-f", help="Perform a full scan, including enumeration."),


):
    """
    Scan a Laravel application for vulnerabilities.
    """
    target_url = normalize_url(target_url)
    print_output.info(f"Scanning target: {target_url}")

    # Initialize HTTP client
    client = http_client

    # 1. Fingerprinting
    print_output.info("Running Fingerprinting module...")
    fingerprint_module = FingerprintModule(target_url, client)
    fingerprint_results = fingerprint_module.run()

    # Placeholder for overall results aggregation
    all_results = {"fingerprint": fingerprint_results}

    # 3. Vulnerability Lookup (if version is found)
    version_info = fingerprint_results.get("Version", {})
    if version_info.get("status") == "FOUND":
        print_output.info("Running Vulnerability Lookup module...")
        
        version_string = version_info.get("version")
        search_version = version_string.split(" ")[-1].replace(".x", "")
        
        # Construct search queries (including the new suggested one)
        queries = [
            f"Laravel {search_version} vulnerability exploit-db",
            f"Laravel {search_version} CVE exploit",
            f"Laravel {search_version} security advisory",
            f"Laravel {search_version} PoC RCE unauthenticated"
        ]
        
        try:
            # Perform the external search
            search_results = search(
                brief=f"Search for Laravel {search_version} vulnerabilities and exploits",
              type='research',
                queries=queries
            )
            

            
            vulnerability_module = VulnerabilityLookupModule(target_url, client)
            vulnerability_results = vulnerability_module.run(version_info, search_results)
            all_results["vulnerability_lookup"] = vulnerability_results
            
        except Exception as e:
            print_output.error(f"Vulnerability Lookup search failed: {e}")

    # 2. Core Security Checks
    print_output.info("Running Core Security Checks module...")
    core_checks_module = CoreChecksModule(target_url, client)
    core_checks_results = core_checks_module.run()
    all_results["core_checks"] = core_checks_results

    # 4. RCE Scanning
    rce_scanner_module = RCEScannerModule(target_url, client)
    rce_results = rce_scanner_module.run(fingerprint_results, core_checks_results)
    all_results["rce_scanner"] = rce_results

    # 5. Enumeration (if full scan)
    if full:
        print_output.info("Running Full Enumeration module...")
        enumeration_module = EnumerationModule(target_url, client)
        enumeration_results = enumeration_module.run()
        all_results["enumeration"] = enumeration_results

    # 6. Output formatting
    format_results(all_results)

    # Close the HTTP client session
    client.close()
    
    print_output.success("Scan finished.")

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show the application version and exit.", is_eager=True
    ),
):
    if version:
        print_output.print_banner()
        raise typer.Exit()

if __name__ == "__main__":
    app()
