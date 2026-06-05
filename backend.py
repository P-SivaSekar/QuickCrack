import hashlib
import json
import os
import sys
import re
from collections import defaultdict
from binascii import hexlify, unhexlify
import hmac

# -----------------------------
# scapy import (used by WPA2 helpers)
# -----------------------------
try:
    from scapy.all import rdpcap, Dot11, EAPOL
except Exception as e:
    rdpcap = None
    Dot11 = None
    EAPOL = None
    SCAPY_IMPORT_ERROR = e
else:
    SCAPY_IMPORT_ERROR = None

# -----------------------------
# Utility functions
# -----------------------------
def resource_path(relative_path):
    """Return a path that works for development and PyInstaller bundles."""
    try:
        base_path = sys._MEIPASS  # type: ignore
    except Exception:
        base_path = os.path.abspath('.')
    return os.path.join(base_path, relative_path)

def read_text_file_with_bom(path):
    with open(path, 'rb') as f:
        raw = f.read()
    text = None
    for enc in ('utf-8-sig', 'utf-16', 'utf-8'):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            text = None
    if text is None:
        text = raw.decode('latin-1', errors='ignore')
    text = text.lstrip('\ufeff').replace('\ufeff', '').replace('ï»¿', '')
    lines = []
    for ln in text.splitlines():
        ln2 = ln.strip()
        if not ln2:
            continue
        if ':' in ln2 and re.search(r'[0-9A-Fa-f]{8,}', ln2.split(':')[-1]):
            ln2 = ln2.split(':')[-1].strip()
        elif ',' in ln2 and re.search(r'[0-9A-Fa-f]{8,}', ln2.split(',')[-1]):
            ln2 = ln2.split(',')[-1].strip()
        ln2 = ln2.lower()
        lines.append(ln2)
    return lines

# -----------------------------
# Rainbow table loader
# -----------------------------
class RainbowTable:
    def __init__(self, files=None):
        self.files = files or ['rainbow_table.json']
        self.table = {}
        self.load()

    def load(self):
        combined = {}
        for f in self.files:
            path = resource_path(f)
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        data = json.load(fh)
                        if isinstance(data, dict):
                            combined.update(data)
                except Exception:
                    try:
                        with open(path, 'r', encoding='latin-1') as fh:
                            data = json.load(fh)
                            if isinstance(data, dict):
                                combined.update(data)
                    except Exception:
                        pass
        self.table = {k.lower(): v for k, v in combined.items()}

    def lookup(self, h):
        return self.table.get(h.lower())

# -----------------------------
# Cracking logic
# -----------------------------
class Cracker:
    def __init__(self, rainbow_table=None, output_cb=None, progress_cb=None):
        self.output_cb = output_cb or (lambda s: None)
        self.progress_cb = progress_cb or (lambda cur, total: None)
        self.rainbow = rainbow_table  # may be None until user explicitly loads it
        self._stop = False

    def stop(self):
        self._stop = True

    def _emit(self, s):
        self.output_cb(s)

    def _progress(self, cur, total):
        self.progress_cb(cur, total)

    def crack(self, hashes, wordlist_words, mode='rainbow', fallback=True):
        self._stop = False
        total = len(hashes)
        results = {}
        md5_map = {}
        sha1_map = {}
        sha256_map = {}
        for w in wordlist_words:
            try:
                b = w.encode('utf-8')
            except Exception:
                b = w.encode('latin-1', errors='ignore')
            md5_map[hashlib.md5(b).hexdigest()] = w
            sha1_map[hashlib.sha1(b).hexdigest()] = w
            sha256_map[hashlib.sha256(b).hexdigest()] = w

        idx = 0
        cracked = 0
        not_found = 0

        for hv in hashes:
            if self._stop:
                self._emit('\n[Stopped by user]\n')
                break
            idx += 1
            self._progress(idx, total)
            self._emit(f"Progress: {idx}/{total} — checking {hv}\n")

            hv_clean = hv.strip().lower()
            if not re.fullmatch(r'[0-9a-f]+', hv_clean):
                self._emit(f"  Skipping (not hex): {hv}\n")
                results[hv] = ('invalid', None)
                not_found += 1
                continue

            found = False
            if mode == 'rainbow':
                if self.rainbow:
                    rt = self.rainbow.lookup(hv_clean)
                    if rt:
                        results[hv] = ('rainbow', rt)
                        self._emit(f"[Rainbow] Found: {rt} for {hv}\n")
                        cracked += 1
                        found = True
                    elif fallback:
                        pass
                    else:
                        results[hv] = ('not_found', None)
                        not_found += 1
                        continue
                else:
                    # Rainbow requested but not loaded
                    self._emit(f"  Rainbow mode requested but rainbow table not loaded — skipping rainbow for {hv}\n")
                    if not fallback:
                        results[hv] = ('not_found', None)
                        not_found += 1
                        continue

            if not found and mode in ('wordlist', 'rainbow'):
                L = len(hv_clean)
                to_try = ['md5'] if L == 32 else ['sha1'] if L == 40 else ['sha256'] if L == 64 else ['md5', 'sha1', 'sha256']
                for alg in to_try:
                    if alg == 'md5' and hv_clean in md5_map:
                        results[hv] = ('md5', md5_map[hv_clean])
                        self._emit(f"[MD5] Found: {md5_map[hv_clean]} for {hv}\n")
                        cracked += 1
                        found = True
                        break
                    if alg == 'sha1' and hv_clean in sha1_map:
                        results[hv] = ('sha1', sha1_map[hv_clean])
                        self._emit(f"[SHA1] Found: {sha1_map[hv_clean]} for {hv}\n")
                        cracked += 1
                        found = True
                        break
                    if alg == 'sha256' and hv_clean in sha256_map:
                        results[hv] = ('sha256', sha256_map[hv_clean])
                        self._emit(f"[SHA256] Found: {sha256_map[hv_clean]} for {hv}\n")
                        cracked += 1
                        found = True
                        break

                if not found:
                    results[hv] = ('not_found', None)
                    not_found += 1

        self._emit(f"\nCracking finished. Cracked: {cracked}, Not Found: {not_found}\n")
        return results

# -----------------------------
# WPA2 verification / EAPOL helpers
# -----------------------------
def pbkdf2_sha1(password: str, ssid: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)

def customPRF512(key: bytes, A: bytes, B: bytes) -> bytes:
    blen = 64
    i = 0
    R = b''
    while len(R) < blen:
        R += hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1).digest()
        i += 1
    return R[:blen]

def mac_to_bytes(mac_str: str) -> bytes:
    return unhexlify(mac_str.replace(':', ''))

def order_pair(a: bytes, b: bytes):
    return (a, b) if a <= b else (b, a)

def scan_eapol_packets(cap_file):
    if rdpcap is None:
        raise RuntimeError("scapy rdpcap not available")
    pkts = rdpcap(cap_file)
    eapol_list = []
    for i, pkt in enumerate(pkts):
        if pkt.haslayer(EAPOL):
            try:
                addr1 = pkt[Dot11].addr1
                addr2 = pkt[Dot11].addr2
            except Exception:
                addr1 = None
                addr2 = None
            raw = bytes(pkt[EAPOL])
            eapol_list.append({
                'index': i,
                'addr1': addr1,
                'addr2': addr2,
                'raw': raw,
                'len': len(raw),
                'pkt': pkt
            })
    return pkts, eapol_list

def parse_eapol_key_fields(raw):
    if len(raw) < 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16:
        return None
    off = 0
    eapol_version = raw[off]
    eapol_type = raw[off+1]
    eapol_len = int.from_bytes(raw[off+2:off+4], 'big')
    off += 4
    key_desc_type = raw[off]
    key_info = int.from_bytes(raw[off+1:off+3], 'big')
    key_length = int.from_bytes(raw[off+3:off+5], 'big')
    off += 5
    replay_counter = raw[off:off+8]; off += 8
    key_nonce = raw[off:off+32]; off += 32
    key_iv = raw[off:off+16]; off += 16
    key_rsc = raw[off:off+8]; off += 8
    key_id = raw[off:off+8]; off += 8
    key_mic = raw[off:off+16]; off += 16
    return {
        'eapol_version': eapol_version,
        'eapol_type': eapol_type,
        'eapol_len': eapol_len,
        'key_desc_type': key_desc_type,
        'key_info': key_info,
        'key_length': key_length,
        'replay_counter': replay_counter,
        'key_nonce': key_nonce,
        'key_iv': key_iv,
        'key_rsc': key_rsc,
        'key_id': key_id,
        'key_mic': key_mic,
        'mic_offset': off - 16
    }

def build_eapol_for_mic(raw, mic_offset):
    if len(raw) < mic_offset + 16:
        return None, None
    eapol_for_mic = raw[:mic_offset] + b'\x00' * 16 + raw[mic_offset+16:]
    mic_bytes = raw[mic_offset:mic_offset+16]
    return eapol_for_mic, mic_bytes

def list_mic_candidates(eapol_list, min_nonzero_bytes=4):
    for entry in eapol_list:
        raw = entry['raw']
        print(f"\nEAPOL pkt idx={entry['index']} addr1={entry['addr1']} addr2={entry['addr2']} len={entry['len']}")
        parsed = parse_eapol_key_fields(raw)
        if parsed:
            off = parsed['mic_offset']
            mic = raw[off:off+16]
            print(f" Standard parsed/mic_offset={off} mic_hex={hexlify(mic).decode()}")
        else:
            print(" Not long enough for standard EAPOL-Key layout parsing.")
        found = False
        for off in range(0, max(1, len(raw)-16)):
            chunk = raw[off:off+16]
            nonzero = sum(1 for b in chunk if b != 0)
            if nonzero >= min_nonzero_bytes:
                found = True
                print(f"  offset={off:3d} hex={hexlify(chunk).decode()} nonzero={nonzero}")
        if not found:
            print("  (no plausible 16-byte non-zero window found in this packet)")

def find_anonce_snonce(eapol_list):
    nonces = []
    for e in eapol_list:
        parsed = parse_eapol_key_fields(e['raw'])
        if parsed:
            key_nonce = parsed['key_nonce']
            if key_nonce not in nonces:
                nonces.append(key_nonce)
    if not nonces:
        return None, None
    if len(nonces) == 1:
        return nonces[0], None
    return nonces[0], nonces[1]

def verify_with_wordlist(hs, wordlist_file, output_cb=print, show_every=1000):
    ssid = hs.get('ssid', 'UNKNOWN_SSID')
    ap_mac = hs.get('ap_mac')
    client_mac = hs.get('client_mac')
    anonce = hs.get('ANonce')
    snonce = hs.get('SNonce')
    eapol_raw = hs.get('eapol_raw')
    mic_offset = hs.get('mic_offset')
    mic_bytes = hs.get('mic_bytes')
    key_info = hs.get('key_info', 0)

    if not (ap_mac and client_mac and eapol_raw is not None and mic_bytes is not None and mic_offset is not None):
        output_cb("Missing components for verification; aborting.\n")
        return False

    eapol_for_mic, captured_mic = build_eapol_for_mic(eapol_raw, mic_offset)
    if eapol_for_mic is None:
        output_cb("Could not construct eapol_for_mic; raw too short for offset.\n")
        return False

    key_descr_ver = key_info & 0x7
    if key_descr_ver == 0:
        mic_alg = 'MD5'
    else:
        mic_alg = 'SHA1'
    output_cb(f"Detected Key Descriptor Version: {key_descr_ver} -> MIC algorithm: {mic_alg}\n")

    output_cb(f"Using SSID: {repr(ssid)}\n")
    output_cb(f"AP MAC: {ap_mac}  Client MAC: {client_mac}\n")
    output_cb(f"Captured MIC (hex at offset {mic_offset}): {hexlify(captured_mic).decode()}\n")

    mac1 = mac_to_bytes(ap_mac)
    mac2 = mac_to_bytes(client_mac)
    mac_min, mac_max = order_pair(mac1, mac2)

    if anonce is None or snonce is None:
        output_cb("Warning: ANonce or SNonce missing — PRF B will be incomplete and verification may fail.\n")
        return False

    nonce_min, nonce_max = order_pair(anonce, snonce)
    B = mac_min + mac_max + nonce_min + nonce_max
    A = b"Pairwise key expansion"

    total = 0
    try:
        with open(wordlist_file, 'rb') as wf:
            for _ in wf:
                total += 1
    except FileNotFoundError:
        output_cb("Wordlist not found: " + str(wordlist_file) + "\n")
        return False

    output_cb(f"Wordlist entries: {total}\n")
    tried = 0
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pwd = line.rstrip('\n')
            tried += 1
            pmk = pbkdf2_sha1(pwd, ssid)
            ptk = customPRF512(pmk, A, B)
            kck = ptk[0:16]
            if mic_alg == 'SHA1':
                mic_calc = hmac.new(kck, eapol_for_mic, hashlib.sha1).digest()[:16]
            else:
                mic_calc = hmac.new(kck, eapol_for_mic, hashlib.md5).digest()[:16]
            if mic_calc == captured_mic:
                output_cb(f"\nPassword found: {pwd} after {tried} attempts\n")
                return True
            if (tried % show_every) == 0:
                output_cb(f"Tried {tried}/{total}...\n")
    output_cb("Password not found in the provided wordlist.\n")
    return False
