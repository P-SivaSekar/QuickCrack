import streamlit as st
import os
import json
import re
import io
from backend import (
    RainbowTable, Cracker,
    read_text_file_with_bom, pbkdf2_sha1, customPRF512,
    mac_to_bytes, order_pair, build_eapol_for_mic, scan_eapol_packets,
    parse_eapol_key_fields, find_anonce_snonce, verify_with_wordlist, SCAPY_IMPORT_ERROR
)

st.set_page_config(page_title="QuickCrack", page_icon="🔐", layout="wide")

st.title("🔐 QuickCrack — Web Interface")
st.markdown("Test out the password cracking capabilities directly in your browser.")

tab1, tab2 = st.tabs(["Hash Cracker", "Wi-Fi Tools"])

with tab1:
    st.subheader("Hash Cracker")
    st.write("Upload a file with hashes (one per line) and a wordlist.")

    hash_file = st.file_uploader("Hash File", type=["txt"])
    wordlist_file = st.file_uploader("Wordlist File", type=["txt"])
    rainbow_file = st.file_uploader("Rainbow Table (JSON) - optional", type=["json"])

    mode = st.radio("Attack Mode", ["rainbow", "wordlist"])
    fallback = st.checkbox("Fall back to wordlist if rainbow fails", value=True)

    if st.button("Start Cracking"):
        if not hash_file:
            st.warning("Please upload a hash file.")
        else:
            with st.spinner("Cracking in progress..."):
                # Read hashes
                hash_content = hash_file.read().decode("utf-8", errors="ignore")
                hashes = []
                for line in hash_content.splitlines():
                    ln = line.strip()
                    if ln:
                        hashes.append(ln)

                # Read wordlist
                words = []
                if wordlist_file:
                    wl_content = wordlist_file.read().decode("utf-8", errors="ignore")
                    for line in wl_content.splitlines():
                        ln = line.strip()
                        if ln:
                            words.append(ln)

                # Read rainbow
                rt = None
                if mode == "rainbow" and rainbow_file:
                    data = json.load(rainbow_file)
                    # mock the files attribute for compatibility
                    rt = RainbowTable(files=[])
                    rt.table = {k.lower(): v for k, v in data.items()}

                output_container = st.empty()
                progress_bar = st.progress(0)

                output_log = []
                def output_cb(msg):
                    output_log.append(msg)
                    # For web, we might not update on every single emit to avoid lag, but this is simple.

                def progress_cb(cur, total):
                    if total > 0:
                        progress_bar.progress(min(cur / total, 1.0))

                cracker = Cracker(rainbow_table=rt, output_cb=output_cb, progress_cb=progress_cb)
                results = cracker.crack(hashes, words, mode=mode, fallback=fallback)
                
                st.success("Cracking finished!")
                
                # Display Results
                st.subheader("Results")
                results_text = ""
                for h, (method, val) in results.items():
                    if method in (None, 'not_found', 'invalid'):
                        res_str = f"{h} : {method}"
                    else:
                        res_str = f"{h} : {method} : {val}"
                    results_text += res_str + "\n"

                st.text_area("Cracking Output", value=results_text, height=300)

                st.download_button(
                    label="Download Results",
                    data=results_text,
                    file_name="cracked_results.txt",
                    mime="text/plain"
                )

with tab2:
    st.subheader("Wi-Fi WPA2 Cracker (Python Verifier)")
    st.write("Upload a `.cap` / `.pcap` handshake file and a wordlist.")
    
    if SCAPY_IMPORT_ERROR:
        st.error(f"Scapy is not available. Wi-Fi tools are disabled. Error: {SCAPY_IMPORT_ERROR}")
    else:
        cap_file = st.file_uploader("Capture File", type=["cap", "pcap"])
        wifi_wordlist = st.file_uploader("Wi-Fi Wordlist File", type=["txt"])

        if st.button("Start Wi-Fi Cracking"):
            if not cap_file or not wifi_wordlist:
                st.warning("Please upload both a capture file and a wordlist.")
            else:
                with st.spinner("Analyzing capture..."):
                    # Save uploaded files temporarily because scapy reads from file paths
                    with open("temp_capture.cap", "wb") as f:
                        f.write(cap_file.read())
                    with open("temp_wordlist.txt", "wb") as f:
                        f.write(wifi_wordlist.read())

                    output_log = []
                    def w_output_cb(msg):
                        output_log.append(msg)
                    
                    try:
                        pkts, eapol_list = scan_eapol_packets("temp_capture.cap")
                        if not eapol_list:
                            st.error("No EAPOL packets found in capture.")
                        else:
                            pkt_entry = max(eapol_list, key=lambda x: x['len'])
                            parsed = parse_eapol_key_fields(pkt_entry['raw'])
                            parsed_mic_offset = parsed['mic_offset'] if parsed else None
                            parsed_key_info = parsed['key_info'] if parsed else 0
                            
                            anonce, snonce = find_anonce_snonce(eapol_list)
                            
                            ssid = 'UNKNOWN_SSID'
                            for p in pkts:
                                try:
                                    if p.haslayer(Dot11) and p.type == 0 and p.subtype == 8:
                                        if hasattr(p, 'info') and p.info:
                                            ssid = p.info.decode(errors='ignore')
                                            break
                                except Exception:
                                    continue

                            hs_base = {
                                'ap_mac': pkt_entry['addr2'],
                                'client_mac': pkt_entry['addr1'],
                                'ANonce': anonce,
                                'SNonce': snonce,
                                'eapol_raw': pkt_entry['raw'],
                                'ssid': ssid
                            }
                            
                            preferred_offsets = []
                            if parsed_mic_offset is not None:
                                preferred_offsets.append(parsed_mic_offset)
                            preferred_offsets += [81, 77, 95, 113, 13]
                            
                            ok_any = False
                            for off in preferred_offsets:
                                eapol_for_mic, mic_bytes = build_eapol_for_mic(pkt_entry['raw'], off)
                                if mic_bytes is None:
                                    continue
                                if all(b == 0x00 for b in mic_bytes):
                                    continue
                                
                                hs = dict(hs_base)
                                hs['mic_offset'] = off
                                hs['mic_bytes'] = mic_bytes
                                hs['key_info'] = parsed_key_info
                                
                                ok = verify_with_wordlist(hs, "temp_wordlist.txt", output_cb=w_output_cb, show_every=500)
                                if ok:
                                    ok_any = True
                                    break
                            
                            st.text_area("Log", value="".join(output_log), height=300)
                            if ok_any:
                                st.success("Password found! See log for details.")
                            else:
                                st.error("Password not found.")
                    finally:
                        if os.path.exists("temp_capture.cap"):
                            os.remove("temp_capture.cap")
                        if os.path.exists("temp_wordlist.txt"):
                            os.remove("temp_wordlist.txt")
