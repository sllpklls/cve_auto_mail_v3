import nvdlib
from datetime import datetime, timezone, timedelta
import requests
import smtplib
import json
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# ================= CẤU HÌNH EMAIL =================
# Cài đặt Gmail - Cần tạo App Password trong Google Account
GMAIL_USER = "automationmailvtb@gmail.com"  # Email gửi
GMAIL_PASSWORD = "cuuy ephf bxzu bjvi"  # App Password (không phải mật khẩu thường)
RECIPIENTS = [
    "hoangthaifc01@gmail.com",
    "hoangnghiathai.01@company.com"
]  # Danh sách email nhận

# ================= CẤU HÌNH CVE =================
# Thời gian
pubStartDate = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y-%m-%d %H:%M")
pubEndDate   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
after_date   = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y-%m-%d")

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
                    "source": set(),
                    "created": getattr(cve, 'published', 'N/A'),
                    "updated": getattr(cve, 'lastModified', 'N/A')
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
            severity = item.get("severity", "UNKNOWN").upper()

            # 👉 Chỉ giữ lại important và critical
            if severity not in ["IMPORTANT", "CRITICAL"]:
                continue  

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
                    "source": set(),
                    "created": public_date or "N/A",
                    "updated": public_date or "N/A"
                }
                redhat_count += 1
                redhat_cve_found = True
                
            cve_dict[cve_id]["affected"].add("Red Hat")
            cve_dict[cve_id]["source"].add("Red Hat")
        
        if redhat_cve_found:
            print(f"  ✅ Red Hat: {redhat_count} CVE (Important/Critical)")
        else:
            print("  🎉 Red Hat: Không có CVE Important/Critical nào!")

    else:
        print(f"  ❌ Lỗi khi gọi API Red Hat: HTTP {resp.status_code}")

except Exception as e:
    print(f"  ❌ Lỗi khi lấy dữ liệu từ Red Hat API: {e}")
# ================= TẠO EMAIL CONTENT =================
def create_email_content(cve_data, windows_found, redhat_found):
    """Tạo nội dung email theo format yêu cầu"""
    
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    filter_date = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    
    # Đếm CVE Windows và Red Hat riêng biệt
    windows_cves = [cve_id for cve_id, data in cve_data.items() if "NVD" in data["source"]]
    redhat_cves = [cve_id for cve_id, data in cve_data.items() if "Red Hat" in data["source"]]
    
    subject = f"CVE Report - {len(windows_cves)} Windows CVE, {len(redhat_cves)} Red Hat CVE - {filter_date}"
    
    email_body = f"""Xin chào,

Microsoft CVE: {len(windows_cves)} CVE từ hôm qua
Red Hat CVE: {len(redhat_cves)} CVE từ hôm qua

"""
    
    # Hiển thị top 10 CVE Windows
    if windows_cves:
        email_body += "=== TOP WINDOWS CVE ===\n"
        count = 1
        for cve_id in sorted(windows_cves)[:10]:
            data = cve_data[cve_id]
            created = data.get('created', 'N/A')
            updated = data.get('updated', 'N/A')
            desc = data['desc'][:80] + "..." if len(data['desc']) > 80 else data['desc']
            
            email_body += f"{count}. {cve_id} | Created: {created} | Updated: {updated}\n"
            email_body += f"    {desc}\n\n"
            count += 1
        
        if len(windows_cves) > 10:
            email_body += f"    ... và {len(windows_cves) - 10} CVE khác (xem file JSON)\n\n"
    
    # Hiển thị top 10 CVE Red Hat
    if redhat_cves:
        email_body += "=== TOP RED HAT CVE ===\n"
        count = 1
        for cve_id in sorted(redhat_cves)[:10]:
            data = cve_data[cve_id]
            created = data.get('created', 'N/A')
            updated = data.get('updated', 'N/A')
            desc = data['desc'][:80] + "..." if len(data['desc']) > 80 else data['desc']
            
            email_body += f"{count}. {cve_id} | Created: {created} | Updated: {updated}\n"
            email_body += f"    {desc}\n\n"
            count += 1
        
        if len(redhat_cves) > 10:
            email_body += f"    ... và {len(redhat_cves) - 10} CVE khác (xem file JSON)\n\n"
    
    if not windows_found and not redhat_found:
        email_body += "🎉 Không có CVE mới nào trong khoảng thời gian này!\n\n"
    
    email_body += f"""Thời gian tạo báo cáo: {current_time}
Nguồn dữ liệu: NVD (nvd.nist.gov) và Red Hat Security Data API
Ngày lọc: {filter_date}

Chi tiết đầy đủ vui lòng xem file JSON đính kèm.

Vui lòng không reply email này, nếu có thắc mắc vui lòng liên hệ Hoàng Thái - hoangnghiathai.01@gmail.com

---
Báo cáo tự động từ CVE Monitor System"""
    
    return subject, email_body

def create_json_attachment(cve_data):
    """Tạo file JSON attachment"""
    # Convert set to list để JSON serialize được
    json_data = {}
    for cve_id, data in cve_data.items():
        json_data[cve_id] = {
            "severity": data["severity"],
            "score": data["score"],
            "description": data["desc"],
            "affected_systems": list(data["affected"]),
            "sources": list(data["source"]),
            "created": data.get("created", "N/A"),
            "updated": data.get("updated", "N/A")
        }
    
    filename = f"cve_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    return filename

def send_email(subject, body, attachment_path=None):
    """Gửi email qua Gmail SMTP"""
    try:
        # Tạo email message
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = ", ".join(RECIPIENTS)
        msg['Subject'] = subject
        
        # Thêm body email
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Thêm attachment nếu có
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {os.path.basename(attachment_path)}'
                )
                msg.attach(part)
        
        # Kết nối SMTP và gửi email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(GMAIL_USER, RECIPIENTS, text)
        server.quit()
        
        print("✅ Email đã được gửi thành công!")
        return True
        
    except Exception as e:
        print(f"❌ Lỗi khi gửi email: {e}")
        return False

# ------------------- In kết quả Console -------------------
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
    
else:
    print("🎉 Tuyệt vời! Không có CVE nghiêm trọng nào trong khoảng thời gian này!")
    print("🔒 Hệ thống hiện tại an toàn từ các lỗ hổng mới.")

# ================= GỬI EMAIL =================
if GMAIL_USER != "your_email@gmail.com" and GMAIL_PASSWORD != "your_app_password":
    print(f"\n📧 Đang chuẩn bị gửi email...")
    
    # Tạo nội dung email
    subject, email_body = create_email_content(cve_dict, windows_cve_found, redhat_cve_found)
    
    # Tạo file JSON attachment
    json_filename = None
    if cve_dict:
        json_filename = create_json_attachment(cve_dict)
        print(f"📎 Đã tạo file attachment: {json_filename}")
    
    # Gửi email
    success = send_email(subject, email_body, json_filename)
    
    # Xóa file JSON sau khi gửi (tuỳ chọn)
    if json_filename and os.path.exists(json_filename):
        try:
            os.remove(json_filename)
            print(f"🗑️ Đã xóa file tạm: {json_filename}")
        except:
            print(f"⚠️ Không thể xóa file tạm: {json_filename}")
            
else:
    print(f"\n⚠️ Chưa cấu hình email. Vui lòng cập nhật GMAIL_USER và GMAIL_PASSWORD để gửi email tự động.")
    print("💡 Hướng dẫn:")
    print("   1. Thay 'your_email@gmail.com' bằng email Gmail của bạn")
    print("   2. Tạo App Password tại: https://myaccount.google.com/apppasswords")
    print("   3. Thay 'your_app_password' bằng App Password vừa tạo")
    print("   4. Cập nhật danh sách RECIPIENTS")