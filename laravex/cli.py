'''
import typer
import sys
from typing import Optional, Any, Dict
from dataclasses import dataclass
from .utils.output import print_output
from .utils.http_client import http_client, normalize_url
from .modules.fingerprint import FingerprintModule
from .modules.core_checks import CoreChecksModule
from .modules.enumerate import EnumerationModule
from .modules.vulnerability_lookup import VulnerabilityLookupModule
from .utils.formatter import format_results



@dataclass
class State:
    pass

app = typer.Typer(
    name="laravex",
    help="Laravex - Laravel Penetration Testing Tool",
    add_completion=False,
    context_settings={"obj": State()}
)

@app.command()
def scan(
    target_url: str = typer.Argument(..., help="The target URL of the Laravel application."),
    full: bool = typer.Option(False, "--full", "-f", help="Perform a full scan, including enumeration."),
    json_output: Optional[str] = typer.Option(None, "--json-output", help="Path to save the scan results in JSON format.")
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
    version_info = fingerprint_results.get('Version', {})
    if version_info.get('status') == 'FOUND':
        print_output.info("Running Vulnerability Lookup module...")
        
        version_string = version_info.get('version')
        search_version = version_string.split(' ')[-1].replace('.x', '')
        
        # Construct search queries (including the new suggested one)
        queries = [
            f'Laravel {search_version} vulnerability exploit-db',
            f'Laravel {search_version} CVE exploit',
            f'Laravel {search_version} security advisory',
            f'Laravel {search_version} PoC RCE unauthenticated'
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

    # 4. Enumeration (if full scan)
    if full:
        print_output.info("Running Full Enumeration module...")
        enumeration_module = EnumerationModule(target_url, client)
        enumeration_results = enumeration_module.run()
        all_results["enumeration"] = enumeration_results

    # 4. Output formatting
    format_results(all_results, json_output)

    # Close the HTTP client session
    client.close()
    
    print_output.success("Scan finished.")

@app.callback()
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show the application version and exit.", is_eager=True
    ),
):
    if version:
        print_output.print_banner()
        raise typer.Exit()

if __name__ == "__main__":
    app()
'''
