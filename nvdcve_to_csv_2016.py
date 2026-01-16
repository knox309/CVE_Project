import json
import csv

# ----------------------
# Files
# ----------------------
json_file = "nvdcve-2.0-2016.json"  # your downloaded JSON file
csv_file = "cves_2016.csv"          # output CSV file

# ----------------------
# Load JSON
# ----------------------
with open(json_file, "r", encoding="utf-8") as f:
    data = json.load(f)

print("Top-level keys:", data.keys())

# In 2016 NVD JSON, CVEs are under 'vulnerabilities'
cve_items = data.get("vulnerabilities", [])
print(f"Found {len(cve_items)} CVEs in 2016 JSON")

# ----------------------
# Extract CVE info
# ----------------------
rows = []

for item in cve_items:
    cve = item.get("cve", {})

    # CVE ID
    cve_id = cve.get("id", "N/A")

    # Published date
    published_date = cve.get("published", "N/A").split("T")[0]

    # Description (English)
    description = "N/A"
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "N/A")
            break

    # Severity (cvss v2 or v3)
    severity = "N/A"
    metrics = item.get("metrics", {})
    if "cvssMetricV2" in metrics:
        severity = metrics["cvssMetricV2"][0]["cvssData"].get("baseSeverity", "N/A")
    elif "cvssMetricV3" in metrics:
        severity = metrics["cvssMetricV3"][0]["cvssData"].get("baseSeverity", "N/A")

    # Affected product/vendor (simplified)
    affected_product = vendor = "N/A"
    try:
        configurations = item.get("configurations", {})
        nodes = configurations.get("nodes", [])
        if nodes:
            cpe_matches = nodes[0].get("cpeMatch", [])
            if cpe_matches:
                cpe_uri = cpe_matches[0].get("criteria", "")
                parts = cpe_uri.split(":")
                if len(parts) > 4:
                    vendor = parts[3]
                    affected_product = parts[4]
    except:
        pass

    rows.append([cve_id, description, published_date, severity, affected_product, vendor])

# ----------------------
# Write CSV
# ----------------------
with open(csv_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["cve_id", "description", "published_date", "severity", "affected_product", "vendor"])
    writer.writerows(rows)

print(f"✅ Converted {len(rows)} CVEs to {csv_file} successfully!")
