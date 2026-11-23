"""
IP Reputation Investigator
Scenario B - COMP H2702 Scripting for Cybersecurity

Analyses a list of IPs against mock reputation data (reproducible),
and demonstrates one live AbuseIPDB CHECK request on an approved IP.
"""

import csv
import ipaddress
import json
import os
import requests

# ---------- Constants ----------
API_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_THRESHOLDS = {"medium_threshold": 25, "high_threshold": 75}
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}


# ---------- Input / configuration ----------
def load_config(path):
    """Load thresholds from JSON; fall back to defaults on any problem."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        medium = int(config["medium_threshold"])
        high = int(config["high_threshold"])
        if not (0 <= medium < high <= 100):
            raise ValueError("thresholds must satisfy 0 <= medium < high <= 100")
        return {"medium_threshold": medium, "high_threshold": high}
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as err:
        print(f"[WARN] Could not use {path} ({err}). Using default thresholds.")
        return dict(DEFAULT_THRESHOLDS)


def load_ip_list(path):
    """Return non-empty, non-comment lines from a text file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f]
    except OSError as err:
        print(f"[ERROR] Cannot read {path}: {err}")
        return []
    return [line for line in lines if line and not line.startswith("#")]


def validate_and_dedupe(raw_ips):
    """Return (valid_unique_ips, invalid_entries), preserving first-seen order."""
    valid, invalid, seen = [], [], set()
    for entry in raw_ips:
        try:
            ip = str(ipaddress.ip_address(entry))   # normalises the format too
        except ValueError:
            invalid.append(entry)
            continue
        if ip in seen:
            continue
        seen.add(ip)
        valid.append(ip)
    return valid, invalid


def load_mock_data(path):
    """Load mock reputation JSON and index it by IP address."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as err:
        print(f"[ERROR] Cannot load mock data {path}: {err}")
        return {}

    # TODO: adapt to YOUR file's structure. Handles two common shapes.
    if isinstance(raw, dict) and "data" not in raw:
        return raw                                   # {"203.0.113.5": {...}}
    records = raw if isinstance(raw, list) else raw.get("data", [])
    return {r.get("ipAddress"): r for r in records if isinstance(r, dict)}


# ---------- API wrapper (request logic ONLY) ----------
def check_ip_live(ip, api_key, max_age_days=90, timeout=10):
    """
    Query AbuseIPDB CHECK for one IP.
    Returns (data_dict, None) on success or (None, error_message) on failure.
    """
    if not api_key:
        return None, "No API key set (environment variable ABUSEIPDB_API_KEY)."
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()["data"], None
    except requests.exceptions.Timeout:
        return None, "Request timed out."
    except requests.exceptions.ConnectionError:
        return None, "Could not connect to AbuseIPDB (network problem?)."
    except requests.exceptions.HTTPError:
        code = response.status_code
        reasons = {401: "Invalid or missing API key", 422: "Invalid request",
                   429: "Daily rate limit exceeded"}
        return None, f"HTTP {code}: {reasons.get(code, 'Server returned an error')}"
    except (ValueError, KeyError):
        return None, "Response was not the expected JSON."
    except requests.exceptions.RequestException as err:
        return None, f"Unexpected request error: {err}"


# ---------- Analysis ----------
def classify_risk(score, whitelisted, thresholds):
    """Map a confidence score (0-100) to LOW / MEDIUM / HIGH."""
    if score is None:
        return "UNKNOWN"
    if whitelisted:
        return "LOW"
    if score >= thresholds["high_threshold"]:
        return "HIGH"
    elif score >= thresholds["medium_threshold"]:
        return "MEDIUM"
    return "LOW"


def analyse_ips(ips, mock_data, thresholds):
    """Build one result dictionary per IP, sorted highest priority first."""
    results = []
    for ip in ips:
        record = mock_data.get(ip)
        if record is None:
            results.append({"ip": ip, "score": None, "country": "N/A",
                            "whitelisted": None, "risk": "UNKNOWN"})
            continue
        score = record.get("abuseConfidenceScore")      # TODO match your field names
        whitelisted = record.get("isWhitelisted", False)
        results.append({
            "ip": ip,
            "score": score,
            "country": record.get("countryCode", "N/A"),
            "whitelisted": whitelisted,
            "risk": classify_risk(score, whitelisted, thresholds),
        })
    results.sort(key=lambda r: (RISK_ORDER[r["risk"]], -(r["score"] or 0)))
    return results


# ---------- Reporting ----------
def generate_report(results, invalid_entries, base_path):
    """Save JSON and CSV reports; print a console summary."""
    os.makedirs(os.path.dirname(base_path), exist_ok=True)
    try:
        with open(base_path + ".json", "w", encoding="utf-8") as f:
            json.dump({"results": results, "invalid_entries": invalid_entries}, f, indent=2)
        with open(base_path + ".csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "score", "country", "whitelisted", "risk"])
            writer.writeheader()
            writer.writerows(results)
    except OSError as err:
        print(f"[ERROR] Could not write report: {err}")
        return

    print(f"\n{'IP':<18}{'SCORE':<8}{'COUNTRY':<9}{'WHITELIST':<11}RISK")
    print("-" * 56)
    for r in results:
        print(f"{r['ip']:<18}{str(r['score']):<8}{r['country']:<9}{str(r['whitelisted']):<11}{r['risk']}")
    print(f"\nInvalid entries skipped: {invalid_entries or 'none'}")
    print(f"Reports saved to {base_path}.json and {base_path}.csv")


# ---------- Main ----------
def main():
    thresholds = load_config("config.json")

    raw = load_ip_list("data/suspicious_ips.txt")
    valid_ips, invalid = validate_and_dedupe(raw)
    print(f"Read {len(raw)} lines -> {len(valid_ips)} valid unique IPs, {len(invalid)} invalid.")

    mock = load_mock_data("data/mock_reputation_data.json")
    results = analyse_ips(valid_ips, mock, thresholds)
    generate_report(results, invalid, "output/report")

    # Live demo: approved IPs ONLY
    print("\n=== Live AbuseIPDB test (approved IPs only) ===")
    live_ips, _ = validate_and_dedupe(load_ip_list("data/approved_live_test_ips.txt"))
    if live_ips:
        data, error = check_ip_live(live_ips[0], os.environ.get("ABUSEIPDB_API_KEY"))
        if error:
            print(f"[LIVE TEST FAILED] {error}")
        else:
            print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()