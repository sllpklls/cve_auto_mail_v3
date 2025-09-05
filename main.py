import nvdlib
from datetime import datetime, timezone

pubStartDate = "2025-08-01 00:00"
pubEndDate   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

# Danh sách CPE chính xác cho Windows Server các bản
cpe_list = [
    "cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
    "cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:*:*",
]

all_results = []

for cpe in cpe_list:
    try:
        results = nvdlib.searchCVE(
            cpeName=cpe,
            pubStartDate=pubStartDate,
            pubEndDate=pubEndDate,
            limit=50   # tăng limit để không bị cắt bớt
        )
        for cve in results:
            score = cve.score[2] if cve.score else "N/A"
            desc = cve.descriptions[0].value if cve.descriptions else "No description"
            severity = cve.score[0] if cve.score else "UNKNOWN"
            all_results.append(f"{cve.id}: {severity} ({score}) - {desc} (CPE={cpe})")
    except Exception as e:
        print(f"Lỗi khi lấy dữ liệu {cpe}: {e}")

# In ra kết quả
for item in all_results:
    print(item)

if not all_results:
    print("⚠️ Không có CVE nào phù hợp (có thể do bộ lọc quá hẹp hoặc chưa có CVE mới).")
