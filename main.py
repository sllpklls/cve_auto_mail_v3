import nvdlib
from datetime import datetime, timezone, timedelta
import requests

# Thời gian
pubStartDate = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d %H:%M")
pubEndDate   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
after_date   = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")

# Chọn mức độ CVE muốn lấy: CRITICAL, HIGH, MEDIUM, LOW, ALL
severity_filter = "ALL"

# Danh sách CPE chính xác cho Windows Server các bản
cpe_map = {
    "cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:*:*": "Windows Server 08",
    "cpe:2.3:o:microsoft:windows_server_2008:r2:*:*:*:*:*:*:*": "Windows Server 08 R2",
    "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*": "Windows Server 12",
    "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*": "Windows Server 12 R2",
    "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*": "Windows Server 16",
    "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*": "Windows Server 19",
    "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*": "Windows Server 22",
    "cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:*:*": "Windows Server 25",
}

# Dict lưu CVE
cve_dict = {}

# ------------------- Lấy CVE từ NVD -------------------
for cpe, short_name in cpe_map.items():
    try:
        kwargs = {
            "cpeName": cpe,
            "pubStartDate": pubStartDate,
            "pubEndDate": pubEndDate,
            "limit": 50
        }
        if severity_filter != "ALL":
            kwargs["cvssV3Severity"] = severity_filter  # lọc theo severity

        results = nvdlib.searchCVE(**kwargs)

        for cve in results:
            cve_id = cve.id
            score = cve.score[2] if cve.score else "N/A"
            desc = cve.descriptions[0].value if cve.descriptions else "No description"
            severity = cve.score[0] if cve.score else "UNKNOWN"

            if cve_id not in cve_dict:
                cve_dict[cve_id] = {
                    "severity": severity,
                    "score": score,
                    "desc": desc,
                    "affected": set(),
                    "source": set()
                }
            cve_dict[cve_id]["affected"].add(short_name)
            cve_dict[cve_id]["source"].add("NVD")

    except Exception as e:
        print(f"Lỗi khi lấy dữ liệu {cpe}: {e}")

# ------------------- Lấy CVE từ Red Hat -------------------
redhat_url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?after={after_date}"

try:
    resp = requests.get(redhat_url, timeout=30)
    if resp.status_code == 200:
        redhat_cves = resp.json()
        for item in redhat_cves:
            cve_id = item.get("CVE")
            severity = item.get("severity", "UNKNOWN")
            desc = item.get("bugzilla_description") or \
                   (item.get("details", ["No description"])[0] if item.get("details") else "No description")
            score = item.get("cvss3_score") or item.get("cvss_score") or "N/A"
            public_date = item.get("public_date")

            if cve_id not in cve_dict:
                cve_dict[cve_id] = {
                    "severity": severity,
                    "score": score,
                    "desc": desc,
                    "affected": set(),
                    "source": set()
                }
            cve_dict[cve_id]["affected"].add("Red Hat")
            cve_dict[cve_id]["source"].add("Red Hat")

    else:
        print(f"⚠️ Lỗi khi gọi API Red Hat: HTTP {resp.status_code}")

except Exception as e:
    print(f"⚠️ Lỗi khi lấy dữ liệu từ Red Hat API: {e}")

# ------------------- In kết quả -------------------
if cve_dict:
    for cve_id, data in cve_dict.items():
        affected_str = ", ".join(sorted(data["affected"]))
        source_str = ", ".join(sorted(data["source"]))
        print(f"{cve_id}: {data['severity']} ({data['score']}) - {data['desc'][:100]}{'...' if len(data['desc']) > 100 else ''} "
              f"[Ảnh hưởng: {affected_str}] [Nguồn: {source_str}]")
else:
    print("⚠️ Không có CVE nào phù hợp.")
