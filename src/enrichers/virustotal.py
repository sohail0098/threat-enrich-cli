import requests

def enrich_virustotal(ioc, api_key):
    headers = {"x-apikey": api_key}
    ioc_type, endpoint = detect_vt_type(ioc)
    if not endpoint:
        return {"ioc": ioc, "source": "VirusTotal", "error": "Unsupported IOC type"}

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values()) or 1
            positives = stats.get("malicious", 0)
            score = round((positives / total) * 100, 2)
            category = data.get("categories") or data.get("meaningful_name", "-")

            return {
                "ioc": ioc,
                "source": "VirusTotal",
                "malicious": positives,
                "total_engines": total,
                "score_percent": score,
                "category": str(category)[:60],
            }
        else:
            return {
                "ioc": ioc,
                "source": "VirusTotal",
                "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
    except Exception as e:
        return {"ioc": ioc, "source": "VirusTotal", "error": str(e)}

def detect_vt_type(ioc):
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip", "ip_addresses"
    if re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "hash", "files"
    if ioc.startswith("http"):
        return "url", "urls"
    if "." in ioc:
        return "domain", "domains"
    return "unknown", None
