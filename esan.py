import re
import json
import base64
from colorama import Fore, Style, init

# 🔥 ข้อความเครดิต
credit_text = """
</>===========================</>
🐝 𝐏𝐲𝐭𝐡𝐨𝐧 𝐁𝐲: 𝗭𝗘�_R𝗢™𝗫 𝗡𝗘𝗧 🐝
</>===========================</>
"""

# รายชื่อแพ็กเกจเป้าหมาย
target_packages = [
    "e3.a",
]

# ฟังก์ชันดึง config.json
def extract_unique_configs(log_file):
    with open(log_file, "r", encoding="utf-8") as file:
        logs = file.readlines()

    extracted = []
    capture = False
    chinese_pattern = re.compile(r'[\u3000-\u9fff]+')

    for line in logs:
        if any(pkg in line for pkg in target_packages):
            capture = True
        elif capture and "->" in line:
            continue
        elif capture and line.strip() and "--------------------" not in line:
            cleaned = chinese_pattern.sub('', line.strip())
            if cleaned.startswith('{"Version"'):
                extracted.append(cleaned)
            capture = False

    return list(set(extracted))  # ลบค่าซ้ำ

# ฟังก์ชันถอดรหัส base64 ถ้าจำเป็น
def decode_base64_fields(json_list):
    decoded_list = []
    for raw in json_list:
        try:
            data = json.loads(raw)
            
            # ถอดรหัสใน setOpenVPN (ถ้ามี)
            if "setOpenVPN" in data and isinstance(data["setOpenVPN"], str):
                data["setOpenVPN"] = try_decode_base64(data["setOpenVPN"])

            # ถอดรหัสใน Networks
            if "Networks" in data:
                for server in data["Networks"]:
                    for key in server.keys():
                        if isinstance(server[key], str):
                            server[key] = try_decode_base64(server[key])

            # ถอดรหัสใน Servers
            if "Servers" in data:
                for server in data["Servers"]:
                    for key in server.keys():
                        if isinstance(server[key], str):
                            server[key] = try_decode_base64(server[key])

            decoded_list.append(data)
        except Exception as e:
            continue
    return decoded_list

# ฟังก์ชันลองถอดรหัส base64 ถ้าจำเป็น
def try_decode_base64(value):
    try:
        # ตรวจสอบว่าเป็น Base64 ที่ถูกต้องหรือไม่
        if re.match(r'^[A-Za-z0-9+/=]+$', value.strip()):
            decoded = base64.b64decode(value.strip()).decode('utf-8')
            return decoded
        return value
    except Exception:
        # ถ้าถอดไม่ได้ ให้คืนค่าเดิม
        return value

# ฟังก์ชันจัด format และ sort key
def format_json_list(json_objects):
    return [json.dumps(obj, indent=4, ensure_ascii=False) for obj in json_objects]

# ฟังก์ชันเพื่อแสดงผลในสี
def print_colored_output(data):
    print(Fore.GREEN + "\n🔹 config.json results 🔹")
    print(Fore.YELLOW + "#====================================#")
    for conf in data:
        print(Fore.CYAN + conf)
        print(Fore.YELLOW + "-" * 40)
    print(Fore.MAGENTA + credit_text)

# 🔥 เริ่มทำงาน
log_file = "/storage/emulated/0/MT2/logs/com.misaki.esanvpn.txt"
configs = extract_unique_configs(log_file)
decoded_configs = decode_base64_fields(configs)
formatted_configs = format_json_list(decoded_configs)

# บันทึกผลลงในไฟล์
output_file = "/storage/emulated/0/ZERO/formatted_config.json"
with open(output_file, "w", encoding="utf-8") as outfile:
    for conf in formatted_configs:
        outfile.write(conf + "\n")

# แสดงผลสีสันใน console
init(autoreset=True)  # ใช้ colorama เพื่อ reset สีหลังการพิมพ์
print_colored_output(formatted_configs)