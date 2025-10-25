import argparse
import yaml
import json
import os
from datetime import datetime, timezone
from enrichers.abuseipdb import enrich_abuseipdb
from enrichers.otx import enrich_otx
from enrichers.virustotal import enrich_virustotal
from utils import (
    detect_ioc_type,
    print_table,
    summarize_results,
    load_cache,
    save_cache,
    is_cache_valid
)
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Enrichment CLI Tool")
    parser.add_argument("--input", help="Single IOC to check (e.g., IP, domain)")
    parser.add_argument("--file", help="File containing list of IOCs")
    parser.add_argument(
        "--sources",
        nargs="+",
        default=["abuseipdb", "otx", "virustotal"],
        help="Sources to query (default: abuseipdb otx virustotal)",
    )
    parser.add_argument("--output", help="Output file (JSON format)", default=None)
    parser.add_argument("--summary", action="store_true", help="Show aggregated summary per IOC")
    parser.add_argument("--cache", help="Cache file path", default="cache.json")
    args = parser.parse_args()

    # Load config
    if not os.path.exists("config.yml"):
        console.print("[red]❌ config.yml not found! Please create the config file with API keys.[/red]")
        return
    with open("config.yml", "r") as f:
        config = yaml.safe_load(f)
    abuseipdb_key = config.get("abuseipdb_api_key")
    otx_key = config.get("otx_api_key")
    vt_key = config.get("virustotal_api_key")

    # Load cache
    cache_file = args.cache
    cache = load_cache(cache_file)
    updated_cache = False

    # Collect IOCs
    iocs = []
    if args.input:
        iocs.append(args.input.strip())
    if args.file and os.path.exists(args.file):
        with open(args.file, "r") as f:
            iocs.extend([line.strip() for line in f if line.strip()])

    if not iocs:
        help_message = """❌ No IOCs provided. Use --input or --file.
    Usage:
    --input <IOC>          Single IOC to check (e.g., IP, domain, hash)
    --file <file_path>     File containing list of IOCs
    --sources <sources>    Sources to query (default: abuseipdb otx virustotal)
    --output <file_path>   Output file (JSON format)
    --summary              Show aggregated summary per IOC
    --cache <file_path>    Cache file path (default: cache.json)"""

        console.print(f"[red]{help_message}[/red]")
        return

    results = []
    for ioc in iocs:
        cache_entry = cache.get(ioc)
        if cache_entry and is_cache_valid(cache_entry):
            console.print(f"[yellow]⚡ Using cached result for {ioc}[/yellow]")
            results.extend(cache_entry["results"])
            continue

        console.print(f"[cyan]🔎 Checking {ioc}...[/cyan]")
        ioc_results = []
        ioc_type = detect_ioc_type(ioc)

        if "abuseipdb" in args.sources and ioc_type == "ip":
            ioc_results.append(enrich_abuseipdb(ioc, abuseipdb_key))
        if "otx" in args.sources:
            ioc_results.append(enrich_otx(ioc, otx_key))
        if "virustotal" in args.sources or "vt" in args.sources:
            ioc_results.append(enrich_virustotal(ioc, vt_key))

        results.extend(ioc_results)
        cache[ioc] = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "results": ioc_results,
        }
        updated_cache = True

    if updated_cache:
        save_cache(cache)

    # Output handling
    print_table(results)

    if args.summary:
        summarize_results(results)

    if args.output:
        with open(args.output, "w") as out:
            json.dump(results, out, indent=2)
        console.print(f"[green]✅ Results saved to {args.output}[/green]")

if __name__ == "__main__":
    main()
