import nvdlib
from datetime import datetime, timezone

pubStartDate = "2025-08-01 00:00"
pubEndDate   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

# Danh sách CPE chính xác cho Windows Server các bản
cpe_map = {
    "cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:*:*": "Windows Server 08",
    "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*": "Windows Server 12",
    "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*": "Windows Server 16",
    "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*": "Windows Server 19",
    "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*": "Windows Server 22",
    "cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:*:*": "Windows Server 25",
}

all_results = []

for cpe, short_name in cpe_map.items():
    try:
        results = nvdlib.searchCVE(
            cpeName=cpe,
            pubStartDate=pubStartDate,
            pubEndDate=pubEndDate,
            limit=50
        )
        for cve in results:
            score = cve.score[2] if cve.score else "N/A"
            desc = cve.descriptions[0].value if cve.descriptions else "No description"
            severity = cve.score[0] if cve.score else "UNKNOWN"
            all_results.append(f"{cve.id}: {severity} ({score}) - {desc} ({short_name})")
    except Exception as e:
        print(f"Lỗi khi lấy dữ liệu {cpe}: {e}")

# In ra kết quả
for item in all_results:
    print(item)

if not all_results:
    print("⚠️ Không có CVE nào phù hợp (có thể do bộ lọc quá hẹp hoặc chưa có CVE mới).")
