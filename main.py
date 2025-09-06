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
windows_cve_found = False  # Flag để theo dõi có CVE Windows nào không

print(f"🔍 Tìm kiếm CVE từ {pubStartDate} đến {pubEndDate}")
print("="*60)

# ------------------- Lấy CVE từ NVD -------------------
print("📊 Đang tìm CVE Windows từ NVD...")

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

        cve_count_for_this_version = 0
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
                windows_cve_found = True  # Đánh dấu đã tìm thấy CVE Windows
                cve_count_for_this_version += 1
            
            cve_dict[cve_id]["affected"].add(short_name)
            cve_dict[cve_id]["source"].add("NVD")

        # Thông báo cho từng phiên bản Windows
        if cve_count_for_this_version > 0:
            print(f"  ✅ {short_name}: {cve_count_for_this_version} CVE")
        else:
            print(f"  ✅ {short_name}: 0 CVE")

    except Exception as e:
        print(f"  ❌ Lỗi khi lấy dữ liệu {short_name}: {e}")

# Thông báo nếu Windows không có CVE nào
if not windows_cve_found:
    print("\n🎉 Tin tốt! Hôm nay Windows không có CVE nào từ NVD.")
else:
    print(f"\n⚠️ Tìm thấy CVE Windows từ NVD!")

# ------------------- Lấy CVE từ Red Hat -------------------
print("\n📊 Đang tìm CVE Red Hat...")
redhat_url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?after={after_date}"
redhat_cve_found = False

try:
    resp = requests.get(redhat_url, timeout=30)
    if resp.status_code == 200:
        redhat_cves = resp.json()
        redhat_count = 0
        
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
                redhat_count += 1
                redhat_cve_found = True
                
            cve_dict[cve_id]["affected"].add("Red Hat")
            cve_dict[cve_id]["source"].add("Red Hat")
        
        if redhat_cve_found:
            print(f"  ✅ Red Hat: {redhat_count} CVE mới")
        else:
            print("  🎉 Red Hat: Không có CVE nào!")

    else:
        print(f"  ❌ Lỗi khi gọi API Red Hat: HTTP {resp.status_code}")

except Exception as e:
    print(f"  ❌ Lỗi khi lấy dữ liệu từ Red Hat API: {e}")

# ------------------- In kết quả -------------------
print(f"\n📈 KẾT QUẢ TỔNG HỢP")
print("="*60)

if cve_dict:
    # Sắp xếp theo độ nghiêm trọng
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sorted_cves = sorted(cve_dict.items(), 
                        key=lambda x: (severity_order.get(x[1]["severity"], 5), x[0]))
    
    # Thêm emoji theo độ nghiêm trọng
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠", 
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "UNKNOWN": "⚪"
    }
    
    for cve_id, data in sorted_cves:
        affected_str = ", ".join(sorted(data["affected"]))
        source_str = ", ".join(sorted(data["source"]))
        emoji = severity_emoji.get(data["severity"], "⚪")
        
        print(f"{emoji} {cve_id}: {data['severity']} ({data['score']}) - {data['desc'][:100]}{'...' if len(data['desc']) > 100 else ''}")
        print(f"   📋 Ảnh hưởng: {affected_str}")
        print(f"   📊 Nguồn: {source_str}")
        print()
    
    print(f"🎯 Tổng cộng: {len(cve_dict)} CVE")
    
    # Thống kê theo độ nghiêm trọng
    severity_stats = {}
    for data in cve_dict.values():
        severity = data["severity"]
        severity_stats[severity] = severity_stats.get(severity, 0) + 1
    
    print("\n📊 Thống kê theo độ nghiêm trọng:")
    for severity, count in sorted(severity_stats.items(), 
                                 key=lambda x: severity_order.get(x[0], 5)):
        emoji = severity_emoji.get(severity, "⚪")
        print(f"   {emoji} {severity}: {count} CVE")
        
    # Thống kê theo nguồn
    print("\n📊 Thống kê theo nguồn:")
    windows_only = sum(1 for data in cve_dict.values() if "NVD" in data["source"] and len(data["source"]) == 1)
    redhat_only = sum(1 for data in cve_dict.values() if "Red Hat" in data["source"] and len(data["source"]) == 1)
    both_sources = sum(1 for data in cve_dict.values() if len(data["source"]) > 1)
    
    if windows_cve_found:
        print(f"   🖥️ Chỉ Windows (NVD): {windows_only} CVE")
    if redhat_cve_found:
        print(f"   🐧 Chỉ Red Hat: {redhat_only} CVE") 
    if both_sources > 0:
        print(f"   🔄 Cả hai nguồn: {both_sources} CVE")
    
else:
    print("🎉 Tuyệt vời! Không có CVE nghiêm trọng nào trong khoảng thời gian này!")
    print("🔒 Hệ thống hiện tại an toàn từ các lỗ hổng mới.")