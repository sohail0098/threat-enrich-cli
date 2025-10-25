import requests

def enrich_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()["data"]
            return {
                "ioc": ip,
                "source": "AbuseIPDB",
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "domain": data.get("domain"),
            }
        else:
            return {"ioc": ip, "source": "AbuseIPDB", "error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"ioc": ip, "source": "AbuseIPDB", "error": str(e)}
