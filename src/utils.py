from datetime import datetime, timedelta, timezone
from rich.console import Console
from rich.table import Table
import re
import json
import os

console = Console()

CACHE_EXPIRY_HOURS = 24 # Cache validity duration in hours

def detect_ioc_type(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "hash"
    if "." in ioc:
        return "domain"
    return "unknown"

def load_cache(cache_file="cache.json"):
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache, cache_file="cache.json"):
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=2)

def is_cache_valid(entry):
    if not entry or "timestamp" not in entry:
        return False
    try:
        timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", ""))
        return datetime.now(timezone.utc) - timestamp < timedelta(hours=CACHE_EXPIRY_HOURS)
    except Exception:
        return False

def print_table(results):
    table = Table(title="[bold cyan]Threat Intel Results[/bold cyan]", show_lines=True)
    columns = [
        "IOC", "Source", "Abuse Score", "Reports", "Pulses", "Tags",
        "Malicious", "Score (%)", "Category", "Error"
    ]
    for col in columns:
        table.add_column(col, style="bold white")

    for r in results:
        table.add_row(
            str(r.get("ioc")),
            str(r.get("source")),
            str(r.get("abuseConfidenceScore", "-")),
            str(r.get("totalReports", "-")),
            str(r.get("pulses", "-")),
            str(r.get("tags", "-")),
            colorize_malicious(r.get("malicious")),
            colorize_score(r.get("score_percent")),
            str(r.get("category", "-")),
            str(r.get("error", "-"))
        )
    console.print(table)

def colorize_score(value):
    if value in (None, "-", ""):
        return "-"
    try:
        val = float(value)
        if val >= 50:
            return f"[bold red]{val}[/bold red]"
        elif val >= 10:
            return f"[yellow]{val}[/yellow]"
        else:
            return f"[green]{val}[/green]"
    except ValueError:
        return str(value)

def colorize_malicious(val):
    if val in (None, "-", ""):
        return "-"
    try:
        v = int(val)
        if v > 5:
            return f"[bold red]{v}[/bold red]"
        elif v > 0:
            return f"[yellow]{v}[/yellow]"
        else:
            return f"[green]{v}[/green]"
    except ValueError:
        return str(val)

def summarize_results(results):
    summary = {}
    for r in results:
        ioc = r.get("ioc")
        if ioc not in summary:
            summary[ioc] = {"sources": 0, "malicious": 0, "errors": 0}

        if r.get("error") and r["error"] != "-":
            summary[ioc]["errors"] += 1
        if r.get("malicious") not in (None, "-", ""):
            try:
                if int(r["malicious"]) > 0:
                    summary[ioc]["malicious"] += 1
            except ValueError:
                pass
        summary[ioc]["sources"] += 1

    table = Table(title="[bold magenta]Summary by IOC[/bold magenta]", show_lines=True)
    table.add_column("IOC", style="bold white")
    table.add_column("Sources Checked", justify="center")
    table.add_column("Malicious Sources", justify="center", style="bold red")
    table.add_column("Errors", justify="center", style="yellow")

    for ioc, vals in summary.items():
        table.add_row(
            ioc,
            str(vals["sources"]),
            str(vals["malicious"]),
            str(vals["errors"]),
        )
    console.print(table)
