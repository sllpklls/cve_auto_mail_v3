import nvdlib
from datetime import datetime, timezone

pubStartDate = "2025-08-01 00:00"
pubEndDate   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

# Chọn mức độ CVE muốn lấy: CRITICAL, HIGH, MEDIUM, LOW, ALL
severity_filter = "CRITICAL"

# Danh sách CPE chính xác cho Windows Server các bản
cpe_map = {
    "cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:*:*": "Windows Server 08",
    "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*": "Windows Server 12",
    "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*": "Windows Server 16",
    "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*": "Windows Server 19",
    "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*": "Windows Server 22",
    "cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:*:*": "Windows Server 25",
}

# Dùng dict để tránh trùng lặp
cve_dict = {}

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
                    "affected": set()
                }
            cve_dict[cve_id]["affected"].add(short_name)

    except Exception as e:
        print(f"Lỗi khi lấy dữ liệu {cpe}: {e}")

# In ra kết quả
if cve_dict:
    for cve_id, data in cve_dict.items():
        affected_str = ", ".join(sorted(data["affected"]))
        print(f"{cve_id}: {data['severity']} ({data['score']}) - {data['desc']} [Ảnh hưởng: {affected_str}]")
else:
    print("⚠️ Không có CVE nào phù hợp (có thể do bộ lọc quá hẹp hoặc chưa có CVE mới).")
