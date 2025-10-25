import requests

def enrich_otx(ioc, api_key):
    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/{detect_type(ioc)}/{ioc}/general"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            tags = data.get("pulse_info", {}).get("pulses", [])
            tag_names = [p.get("name") for p in tags[:3]]  # only first 3 for brevity
            return {
                "ioc": ioc,
                "source": "OTX",
                "pulses": pulses,
                "tags": ", ".join(tag_names) if tag_names else "-",
            }
        else:
            return {"ioc": ioc, "source": "OTX", "error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"ioc": ioc, "source": "OTX", "error": str(e)}

def detect_type(ioc):
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IPv4"
    if re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "file"
    if "." in ioc:
        return "domain"
    return "url"
