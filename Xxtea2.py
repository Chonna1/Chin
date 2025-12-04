import sys
import json
import requests
import base64
import os
import time
import itertools

# ======================= ตั้งค่า URL และ KEY ตรงนี้ =======================
TARGET_URL = "https://raw.githubusercontent.com/TinSoeOo077/Ahpaim/refs/heads/main/Net.Json"  # ← ใส่ URL ของคุณที่นี่
XXTEA_KEY  = "6465"                      # ← ใส่ Key XXTEA ของคุณที่นี่
# ======================================================================

# ======================= COLOR =======================
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; C = "\033[96m"; P = "\033[95m"
    W = "\033[97m"; N = "\033[0m"

def success(m): print(f"{C.G}[+] {C.W}{m}{C.N}")
def error(m):   print(f"{C.R}[-] {C.W}{m}{C.N}")
def info(m):    print(f"{C.C}[*] {C.W}{m}{C.N}")

def spinner(msg, t=1.2):
    for c in itertools.cycle(['-', '\\', '|', '/']):
        print(f"\r{C.P}[~] {msg} {c}{C.N}", end="")
        time.sleep(0.1)
        t -= 0.1
        if t <= 0: break
    print("\r" + " " * 80 + "\r", end="")

# ======================= XXTEA DECRYPTION =======================
D = 0x2e0ba747

def sh(v, c): return (v & 0xFFFFFFFF) >> c

def bti(d, inc_l):
    if not d: return []
    ni = (len(d) + 3) // 4
    il = [0] * (ni + (1 if inc_l else 0))
    if inc_l: il[ni] = len(d)
    for i in range(len(d)):
        li = i >> 2
        bs = (i & 3) << 3
        il[li] |= (d[i] & 0xFF) << bs
    return il

def itb(il, has_l):
    if not il: return None
    nb = len(il) << 2
    if has_l:
        ol = il[-1]
        if ol > nb or ol < 0: return None
        nb = ol
    rb = bytearray(nb)
    for i in range(nb):
        li = i >> 2
        if li >= len(il): break
        bs = (i & 3) << 3
        rb[i] = (sh(il[li], bs)) & 0xFF
    return rb

def nk(k):
    n = bytearray(16)
    cl = min(len(k), 16)
    n[:cl] = k[:cl]
    return n

def mx(p0, p1, p2, p3, p4, p5):
    v0 = sh(p2, 5) ^ (p1 << 2)
    v1 = sh(p1, 3) ^ (p2 << 4)
    sv = (v0 + v1) & 0xFFFFFFFF
    sp = ((p0 ^ p1) + (p5[(p3 & 3) ^ p4] ^ p2)) & 0xFFFFFFFF
    return (sp ^ sv) & 0xFFFFFFFF

def dec_r(db, kb):
    if not db: return db
    nb = len(db) - 1
    if nb < 1: return db
    nr = (52 // (nb + 1)) + 6
    cb = db[0]
    rs = (nr * D) & 0xFFFFFFFF
    while rs != 0:
        ms = sh(rs, 2) & 3
        pb = cb
        for p in range(nb, 0, -1):
            mr = mx(rs, pb, db[p - 1], p, ms, kb)
            pb = (db[p] - mr) & 0xFFFFFFFF
            db[p] = pb
        mr = mx(rs, pb, db[nb], 0, ms, kb)
        cb = (db[0] - mr) & 0xFFFFFFFF
        db[0] = cb
        rs = (rs - D) & 0xFFFFFFFF
    return db

def decrypt_xxtea(enc: str, key: str) -> str | None:
    try:
        eb = base64.b64decode(enc)
        kb = key.encode('utf-8')
        nk_b = nk(kb)
        db = bti(eb, False)
        kb_int = bti(nk_b, False)
        ddb = dec_r(db, kb_int)
        rb = itb(ddb, True)
        return rb.decode('utf-8', errors='ignore') if rb else None
    except:
        return None

# ======================= UNICODE FIX =======================
def fix_unicode(text: str, key_str: str) -> str:
    if not text: return ""
    try:
        offset = int(key_str)
    except:
        offset = 6465
    shift = offset * 2
    result = []
    for c in text:
        cp = (ord(c) - shift) & 0x10FFFF
        if 0xD800 <= cp <= 0xDFFF:
            cp = 0x003F  # แทนที่ surrogate ด้วย ?
        result.append(chr(cp))
    return ''.join(result)

# ======================= FIELD DECRYPTION =======================
def decrypt_field(value: str, key: str) -> str:
    if not value or not isinstance(value, str):
        return value
    dec = decrypt_xxtea(value, key)
    return fix_unicode(dec, key) if dec else value

def decrypt_all(data, key: str):
    if isinstance(data, dict):
        for k, v in data.items():
            if k in ["NetworkPayload","ovpnCertificate","ProxyHost","SSLSNI","SlowIP",
                     "PublicKey","SquidProxy","ServerIP","ServerCloudFront","config_url","ServerHTTP",
                     "Username","Password","Host","Port"]:
                data[k] = decrypt_field(v, key)
            else:
                decrypt_all(v, key)
    elif isinstance(data, list):
        for item in data:
            decrypt_all(item, key)
    return data

# ======================= MAIN =======================
if __name__ == "__main__":
    print(f"{C.P}╔{'═'*54}╗")
    print(f"║{'      XXTEA CONFIG SNIFFER / DUMPER      '.center(54)}║")
    print(f"╚{'═'*54}╝{C.N}\n")

    # ตรวจสอบว่ามีการตั้งค่า URL และ Key หรือยัง
    if not TARGET_URL or TARGET_URL == "https://example.com/your_config.txt":
        error("กรุณาแก้ไข TARGET_URL ในสคริปต์ก่อนใช้งาน!")
        sys.exit(1)
    if not XXTEA_KEY or XXTEA_KEY == "1234567890abcdef":
        error("กรุณาแก้ไข XXTEA_KEY ในสคริปต์ก่อนใช้งาน!")
        sys.exit(1)

    URL = TARGET_URL.strip()
    KEY = XXTEA_KEY.strip()

    headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 10; K)"}
    save_path = "/storage/emulated/0/ZERO/Xxtea_Dumper.txt"

    try:
        info("Connecting to target...")
        spinner("Fetching payload", 1.5)
        r = requests.get(URL, headers=headers, timeout=40)
        r.raise_for_status()

        payload = r.text.strip()
        info("Decrypting outer XXTEA layer...")
        spinner("Processing", 1.5)
        outer = decrypt_xxtea(payload, KEY)
        if not outer:
            error("Failed to decrypt! Wrong key or corrupted payload")
            sys.exit(1)

        info("𝗭𝗘𝗥𝗢™𝗫 𝗡𝗘𝗧")
        json_text = fix_unicode(outer, KEY)

        info("Parsing JSON structure...")
        data = json.loads(json_text)

        info("Decrypting all encrypted fields...")
        spinner("Finalizing", 2)
        final = decrypt_all(data, KEY)

        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(final, f, indent=4, ensure_ascii=False)

        print("\n" + C.P + "═"*66 + C.N)
        print(f"{C.G}          DECRYPTION SUCCESSFUL - CONFIG DUMPED          {C.N}")
        print(C.P + "═"*66 + C.N)
        print(C.G + json.dumps(final, indent=4, ensure_ascii=False) + C.N)
        print(C.P + "═"*66 + C.N)
        success(f"Saved to → {os.path.abspath(save_path)}")

    except requests.exceptions.RequestException as e:
        error(f"Network error: {e}")
    except json.JSONDecodeError as e:
        error(f"JSON parse failed (อาจเป็นเพราะ Key ผิด): {e}")
    except Exception as e:
        error(f"Unexpected error: {e}")