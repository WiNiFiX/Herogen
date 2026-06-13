import sqlite3
import json
import os
import base64
import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- DPAPI decryption -------------------------------------------------------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_char))]

def dpapi_decrypt(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in  = DATA_BLOB(ctypes.sizeof(buf), buf)
    blob_out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0,
        ctypes.byref(blob_out))
    if not ok:
        raise RuntimeError("DPAPI decryption failed")
    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return result

# ---- Get Chrome AES key -----------------------------------------------------

local_state = os.path.join(os.environ['LOCALAPPDATA'],
    'Google', 'Chrome', 'User Data', 'Local State')
with open(local_state, 'r', encoding='utf-8') as f:
    state = json.load(f)

enc_key_b64 = state['os_crypt']['encrypted_key']
enc_key = base64.b64decode(enc_key_b64)[5:]   # strip leading b'DPAPI'
aes_key = dpapi_decrypt(enc_key)

# ---- Decrypt a single cookie value ------------------------------------------

def decrypt_value(encrypted_value: bytes, value: str, name: str = '') -> str:
    if not encrypted_value:
        return value or ''
    prefix = encrypted_value[:3]
    print(f"    [debug] name={name} prefix={prefix} total_len={len(encrypted_value)}")
    if prefix in (b'v10', b'v11'):
        nonce      = encrypted_value[3:15]
        ciphertext = encrypted_value[15:]
        try:
            return AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception as e:
            return f'[decrypt error v10/v11: {type(e).__name__}: {e}]'
    if prefix == b'v20':
        # Chrome 127+ App-Bound Encryption — not decryptable without Chrome IPC
        return '[v20 app-bound encryption — needs special handling]'
    # Unknown prefix — try as plaintext
    try:
        return encrypted_value.decode('utf-8')
    except Exception:
        return f'[unknown prefix {prefix}]'

# ---- Query cookies ----------------------------------------------------------

cookie_names = [
    'info', 'skills', 'other', 'custom',
    'info_0', 'skills_0', 'other_0', 'custom_0',
    'info_1', 'skills_1', 'other_1', 'custom_1',
    'info_2', 'skills_2', 'other_2', 'custom_2',
    'weapons_armor_perks_flaws',
]

db_path = os.path.join(os.environ['TEMP'], 'chrome_cookies.db')
conn = sqlite3.connect(db_path)
cur  = conn.cursor()

placeholders = ','.join('?' * len(cookie_names))
cur.execute(
    f'SELECT host_key, name, value, encrypted_value '
    f'FROM cookies WHERE name IN ({placeholders})',
    cookie_names
)
rows = cur.fetchall()
conn.close()

if not rows:
    print("No HeroGen cookies found in Chrome.")
    print("\nAll cookie names present in DB:")
    conn2 = sqlite3.connect(db_path)
    cur2  = conn2.cursor()
    cur2.execute("SELECT DISTINCT host_key, name FROM cookies ORDER BY host_key, name")
    for h, n in cur2.fetchall():
        print(f"  {h}  {n}")
    conn2.close()
else:
    results = {}
    for host_key, name, value, enc_val in rows:
        decrypted = decrypt_value(enc_val, value, name)
        print(f"HOST: [{host_key}]  NAME: [{name}]")
        print(f"  VALUE: {decrypted[:120]}")
        print()
        results[name] = {'host': host_key, 'raw_escaped': decrypted}

    # Emit JS cookie-setter snippet for localhost
    print("\n--- JavaScript to paste in DevTools Console on localhost ---")
    print("(Open http://localhost/herogen/import_cookies.htm in Chrome,")
    print(" open F12 Console, paste the block below, then refresh index.htm)\n")
    for name, info in results.items():
        val = info['raw_escaped'].replace('\\', '\\\\').replace("'", "\\'")
        print(f"document.cookie = \"{name}=\" + escape('{val}') + \"; expires=\" + new Date(Date.now()+365*864e5).toGMTString() + \"; path=/\";")
