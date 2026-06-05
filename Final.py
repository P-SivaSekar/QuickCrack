#!/usr/bin/env python3
"""
QuickCrack — Password Cracker GUI (Colorful UI + Background + Rainbow load-on-demand)

Changes made from your last UI-redesign:
 - Colorful, modern-looking accents and larger fonts.
 - Background image support (load "background.png" from app folder or bundled resources).
 - "About Project" button that opens a web page with project info (change URL as you prefer).
 - Rainbow table is NOT preloaded at startup. A dedicated "Load Rainbow Table" button (and an
   "Enable Rainbow Table" checkbox) lets the user load the rainbow table into memory on-demand.
 - When rainbow table is loaded, the Cracker instance's rainbow pointer is updated, so all
   cracking operations use it. If the user doesn't load it, memory is saved.
 - Minimal functional changes to the cracking / WPA2 / aircrack logic — only UI and loading behavior changed.

Drop a "background.png" next to this script (or bundled via PyInstaller) to use the background image.
You can change the ABOUT_URL constant to point to your project's web page.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import scrolledtext
import threading
import os
import sys
import subprocess
import webbrowser
from binascii import hexlify
from backend import (
    resource_path, read_text_file_with_bom, RainbowTable, Cracker,
    scan_eapol_packets, parse_eapol_key_fields, build_eapol_for_mic,
    find_anonce_snonce, verify_with_wordlist, SCAPY_IMPORT_ERROR,
    Dot11
)

# -----------------------------
# GUI (colorful + background + on-demand rainbow load)
# -----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('🔐 QuickCrack — Password Cracker')
        self.geometry('1200x820')
        self.minsize(1000, 650)
        # base background color (used if background image not found)
        self.configure(bg='#0f1724')

        # ---------- Styles ----------
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass

        DEFAULT_FONT = ('Segoe UI', 10)
        HEADER_FONT = ('Segoe UI', 14, 'bold')
        BIG_FONT = ('Segoe UI', 11)
        style.configure('.', background='#0f1724', foreground='#008000', font=DEFAULT_FONT)
        style.configure('Card.TFrame', background='#0b1220', relief='flat')
        style.configure('Header.TLabel', font=HEADER_FONT, background='#0f1724', foreground='#ffe8a1')
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'), foreground='#ffffff')
        style.map('Accent.TButton', background=[('active', '#ff7a59')], foreground=[('active', '#ffffff')])
        style.configure('Danger.TButton', background='#ff6b6b', foreground='#ffffff')
        style.configure('SubHeader.TLabel', font=BIG_FONT, background='#0f1724', foreground='#bfe6ff')

        # ---------- Background image ----------
        self._bg_image = None
        bg_path = resource_path(BACKGROUND_IMAGE)
        if os.path.exists(bg_path):
            try:
                self._bg_image = tk.PhotoImage(file=bg_path)
                self._bg_label = tk.Label(self, image=self._bg_image)
                self._bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)
            except Exception:
                self._bg_image = None

        # ---------- Top bar ----------
        topbar = ttk.Frame(self, style='Card.TFrame')
        topbar.pack(fill='x', padx=12, pady=10)
        ttk.Label(topbar, text='QuickCrack', style='Header.TLabel').pack(side='left', padx=(8, 6))
        ttk.Label(topbar, text='Password Cracking Toolkit', style='SubHeader.TLabel').pack(side='left', padx=(4, 8))

        # About button (opens web page)
        about_btn = ttk.Button(topbar, text='About Project', style='Accent.TButton', command=self._open_about)
        about_btn.pack(side='right', padx=8)
        # Rainbow load button (distinct)
        self.load_rain_btn = ttk.Button(topbar, text='Load Rainbow Table', command=self._load_rainbow_button_click)
        self.load_rain_btn.pack(side='right', padx=8)







        # Main area
        main_pane = tk.Frame(self, bg=self["bg"])
        main_pane.pack(fill='both', expand=True, padx=12, pady=(0,12))

        # Left: controls (colorful card)
        left = ttk.Frame(main_pane, width=420, style='Card.TFrame', padding=(12,12))
        left.pack(side='left', fill='y', padx=(0,12), pady=4)

        notebook = ttk.Notebook(left)
        notebook.pack(fill='both', expand=True)

        # --- Tab: Hash Cracker ---
        tab_hash = ttk.Frame(notebook, padding=(10,10), style='Card.TFrame')
        notebook.add(tab_hash, text='Hash Cracker')

        ttk.Label(tab_hash, text='Hash file (one per line):').grid(row=0, column=0, sticky='w')
        self.hash_entry = ttk.Entry(tab_hash, width=40)
        self.hash_entry.grid(row=1, column=0, sticky='we', pady=(4,6))
        ttk.Button(tab_hash, text='Browse', command=lambda: self._select_file(self.hash_entry)).grid(row=1, column=1, padx=(6,0))

        ttk.Label(tab_hash, text='Wordlist file:').grid(row=2, column=0, sticky='w', pady=(8,0))
        self.word_entry = ttk.Entry(tab_hash, width=40)
        self.word_entry.grid(row=3, column=0, sticky='we', pady=(4,6))
        ttk.Button(tab_hash, text='Browse', command=lambda: self._select_file(self.word_entry)).grid(row=3, column=1, padx=(6,0))

        # Rainbow control
        ttk.Label(tab_hash, text='Rainbow table (optional):').grid(row=4, column=0, sticky='w', pady=(8,0))
        self.rain_entry = ttk.Entry(tab_hash, width=30)
        self.rain_entry.insert(0, 'rainbow_table.json')
        self.rain_entry.grid(row=5, column=0, sticky='we', pady=(4,6))
        ttk.Button(tab_hash, text='Browse', command=lambda: self._select_file(self.rain_entry)).grid(row=5, column=1, padx=(6,0))

        # Checkbox to indicate whether rainbow should be used if loaded
        self.use_rain_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab_hash, text='Use rainbow if loaded', variable=self.use_rain_var).grid(row=6, column=0, sticky='w', pady=(8,0))

        ttk.Label(tab_hash, text='Attack Mode:').grid(row=7, column=0, sticky='w', pady=(10,0))
        self.mode_var = tk.StringVar(value='rainbow')
        rb_frame = ttk.Frame(tab_hash)
        rb_frame.grid(row=8, column=0, columnspan=2, sticky='w')
        ttk.Radiobutton(rb_frame, text='Rainbow (default)', variable=self.mode_var, value='rainbow').pack(anchor='w')
        ttk.Radiobutton(rb_frame, text='Wordlist only', variable=self.mode_var, value='wordlist').pack(anchor='w')
        self.fallback_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab_hash, text='If rainbow fails, fall back to wordlist', variable=self.fallback_var).grid(row=9, column=0, sticky='w', pady=(8,0))

        # Action buttons
        action_frame = ttk.Frame(tab_hash)
        action_frame.grid(row=10, column=0, columnspan=2, pady=(12,0))
        self.start_btn = ttk.Button(action_frame, text='Start Cracking', style='Accent.TButton', command=self.start)
        self.start_btn.grid(row=0, column=0, padx=(0,6))
        self.stop_btn = ttk.Button(action_frame, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=(0,6))
        self.save_btn = ttk.Button(action_frame, text='Save Results', command=self.save_results)
        self.save_btn.grid(row=0, column=2, padx=(0,6))

        # --- Tab: Wi-Fi Tools ---
        tab_wifi = ttk.Frame(notebook, padding=(10,10), style='Card.TFrame')
        notebook.add(tab_wifi, text='Wi-Fi Tools')

        ttk.Label(tab_wifi, text='Wi-Fi handshake / capture helpers').pack(anchor='w')
        ttk.Label(tab_wifi, text='(Use Python verifier or Aircrack-ng below)').pack(anchor='w', pady=(0,6))

        self.aircrack_btn = ttk.Button(tab_wifi, text='Wi-Fi Crack (Aircrack-ng)', command=self.start_aircrack)
        self.aircrack_btn.pack(fill='x', pady=(6,4))
        self.python_crack_btn = ttk.Button(tab_wifi, text='Wi-Fi Crack (Python verifier)', command=self.start_python_wpa2_crack)
        self.python_crack_btn.pack(fill='x')

        if SCAPY_IMPORT_ERROR:
            ttk.Label(tab_wifi, text=f'scapy not available: {SCAPY_IMPORT_ERROR}', foreground='#ffb3b3').pack(anchor='w', pady=(8,0))

        # Right: output (large colorful card)
        right = ttk.Frame(main_pane, style='Card.TFrame', padding=(10,10))
        right.pack(side='right', fill='both', expand=True)

        out_header = ttk.Frame(right, style='Card.TFrame')
        out_header.pack(fill='x')
        ttk.Label(out_header, text='Output:', style='Header.TLabel').pack(side='left')
        self.status_label = ttk.Label(out_header, text='Ready', background='#0f1724', foreground='#bfe6ff')
        self.status_label.pack(side='right')

        self.output = scrolledtext.ScrolledText(right, wrap='word', bg='#071226', fg='#e6eef8', insertbackground='white', height=20)
        self.output.pack(fill='both', expand=True, padx=(6,0), pady=(6,6))

        footer = ttk.Frame(right, style='Card.TFrame')
        footer.pack(fill='x')
        self.progress = ttk.Progressbar(footer, orient='horizontal', mode='determinate')
        self.progress.pack(fill='x', side='left', expand=True, padx=(4,4), pady=(6,6))

        # ---------- Internal state ----------
        self.rainbow_table = None  # will be loaded only when the user requests it
        self.rainbow_loaded = False
        self._append_output("Rainbow table is currently NOT loaded. Click 'Load Rainbow Table' to load it into memory.\n")

        # create Cracker with no rainbow initially
        self.cracker = Cracker(rainbow_table=None, output_cb=self._append_output, progress_cb=self._update_progress)
        self._worker_thread = None
        self._last_results = None

        if SCAPY_IMPORT_ERROR:
            self._append_output(f"Warning: scapy import failed ({SCAPY_IMPORT_ERROR}). WPA2 Python verifier will be unavailable.\n")

    # -----------------------------
    # Helper methods
    # -----------------------------
    def _open_about(self):
        try:
            webbrowser.open(ABOUT_URL, new=2)
        except Exception:
            messagebox.showinfo("About", f"Project info page: {ABOUT_URL}")

    def _select_file(self, entry_widget):
        file_path = filedialog.askopenfilename(filetypes=[('All files', '*.*')])
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)

    def _append_output(self, s):
        self.after(0, lambda: (self.output.insert(tk.END, s), self.output.see(tk.END)))

    def _update_progress(self, cur, total):
        def upd():
            self.progress['maximum'] = total or 1
            self.progress['value'] = cur
            self.status_label.config(text=f'Progress: {cur}/{total}')
        self.after(0, upd)

    def _set_ui_state(self, running=True):
        self.start_btn.config(state='disabled' if running else 'normal')
        self.stop_btn.config(state='normal' if running else 'disabled')
        self.save_btn.config(state='disabled' if running else 'normal')
        self.aircrack_btn.config(state='disabled' if running else 'normal')
        self.python_crack_btn.config(state='disabled' if running else 'normal')
        self.load_rain_btn.config(state='disabled' if running else 'normal')

    # -----------------------------
    # Rainbow load-on-demand
    # -----------------------------
    def _load_rainbow_button_click(self):
        """
        When the user clicks the topbar 'Load Rainbow Table' button, load the file from the
        path in self.rain_entry. This will populate self.rainbow_table and attach it to
        self.cracker.rainbow. Loading happens in a worker thread to avoid GUI freeze.
        """
        rainbow_path = self.rain_entry.get().strip()
        if not rainbow_path:
            messagebox.showwarning('Rainbow Table', 'Please provide a rainbow table path (JSON).')
            return
        if not os.path.exists(rainbow_path):
            messagebox.showerror('Rainbow Table', f'File not found: {rainbow_path}')
            return

        # disable button to prevent double-click
        self.load_rain_btn.config(state='disabled')
        self._append_output(f"Starting to load rainbow table from {rainbow_path}...\n")
        self.status_label.config(text='Loading rainbow table...')

        def worker():
            try:
                rt = RainbowTable(files=[rainbow_path])
                self.rainbow_table = rt
                self.cracker.rainbow = rt
                self.rainbow_loaded = True
                self._append_output("Rainbow table loaded into memory (on-demand).\n")
            except Exception as e:
                self._append_output(f"Failed to load rainbow table: {e}\n")
                self.rainbow_table = None
                self.rainbow_loaded = False
            finally:
                self.after(0, lambda: (self.load_rain_btn.config(state='normal'), self.status_label.config(text='Ready')))

        threading.Thread(target=worker, daemon=True).start()

    # -----------------------------
    # Actions (unchanged behaviour aside from rainbow handling)
    # -----------------------------
    def start(self):
        hash_file = self.hash_entry.get().strip()
        word_file = self.word_entry.get().strip()
        mode = self.mode_var.get()
        fallback = self.fallback_var.get()
        use_rain_if_loaded = self.use_rain_var.get()

        if not hash_file or not os.path.exists(hash_file):
            messagebox.showwarning('Select Hash File', 'Please choose a valid hash file.')
            return

        words = []
        if os.path.exists(word_file):
            try:
                words = read_text_file_with_bom(word_file)
            except Exception:
                words = []

        # If the user selected rainbow mode but rainbow is not loaded and they unchecked fallback,
        # warn them — but still allow run.
        if mode == 'rainbow' and not self.rainbow_loaded and not fallback:
            if not messagebox.askyesno("Rainbow not loaded", "Rainbow mode requested but rainbow table is not loaded. Continue (will skip rainbow)?"):
                return

        self.output.delete(1.0, tk.END)
        self.progress['value'] = 0
        self._set_ui_state(running=True)
        self.status_label.config(text='Starting...')

        def worker():
            try:
                # If rainbow should be used when loaded, ensure cracker.rainbow is set (already done on load)
                if use_rain_if_loaded and self.rainbow_loaded:
                    self.cracker.rainbow = self.rainbow_table
                else:
                    # If the user doesn't want to use rainbow, ensure it's None so we don't consume it.
                    if not use_rain_if_loaded:
                        self.cracker.rainbow = None

                self._last_results = self.cracker.crack(read_text_file_with_bom(hash_file), words, mode=mode, fallback=fallback)
            except Exception as ex:
                self._append_output(f'Error during cracking: {ex}\n')
                self._last_results = None
            finally:
                self.after(0, lambda: (self._set_ui_state(running=False), self.status_label.config(text='Done')))

        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()

    def stop(self):
        if self._worker_thread and self._worker_thread.is_alive():
            self.cracker.stop()
            self._append_output('\nStopping... please wait.\n')

    def save_results(self):
        if not self._last_results:
            messagebox.showinfo('No results', 'No results to save. Run a cracking session first.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text files','*.txt'), ('All files','*.*')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                for h, (method, val) in self._last_results.items():
                    if method in (None, 'not_found', 'invalid'):
                        fh.write(f"{h} : {method}\n")
                    else:
                        fh.write(f"{h} : {method} : {val}\n")
            messagebox.showinfo('Saved', f'Results saved to {path}')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save results: {e}')

    # -----------------------------
    # Python WPA2 cracker (same behaviour)
    # -----------------------------
    def start_python_wpa2_crack(self):
        if SCAPY_IMPORT_ERROR:
            messagebox.showerror("scapy missing", f"scapy is required for the Python WPA2 verifier. Import error: {SCAPY_IMPORT_ERROR}")
            return

        cap_file = filedialog.askopenfilename(title="Select Handshake File", filetypes=[("Capture files", "*.cap *.pcap")])
        if not cap_file:
            return
        wordlist_file = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text files", "*.txt")])
        if not wordlist_file:
            return

        self.output.delete(1.0, tk.END)
        self._set_ui_state(running=True)
        self.status_label.config(text='Running Python WPA2 Cracker...')

        def worker():
            try:
                pkts, eapol_list = scan_eapol_packets(cap_file)
                if not eapol_list:
                    self._append_output("No EAPOL packets found in capture.\n")
                    return

                pkt_entry = max(eapol_list, key=lambda x: x['len'])
                parsed = parse_eapol_key_fields(pkt_entry['raw'])
                parsed_mic_offset = parsed['mic_offset'] if parsed else None
                parsed_key_info = parsed['key_info'] if parsed else 0
                parsed_nonce = parsed['key_nonce'] if parsed else None

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
                        self._append_output(f"Offset {off} not valid for this packet (length {pkt_entry['len']}). Skipping.\n")
                        continue
                    if all(b == 0x00 for b in mic_bytes):
                        self._append_output(f"Offset {off} MIC all zeros; skipping.\n")
                        continue

                    self._append_output(f"\nAttempting with packet idx={pkt_entry['index']} offset={off} mic_hex={hexlify(mic_bytes).decode()}\n")
                    hs = dict(hs_base)
                    hs['mic_offset'] = off
                    hs['mic_bytes'] = mic_bytes
                    hs['key_info'] = parsed_key_info

                    ok = verify_with_wordlist(hs, wordlist_file, output_cb=self._append_output, show_every=500)
                    if ok:
                        ok_any = True
                        break

                if not ok_any:
                    self._append_output("\nTried preferred offsets; no password found. Use --list equivalent to inspect MIC candidate offsets.\n")
            except Exception as e:
                self._append_output(f"Error: {e}\n")
            finally:
                self.after(0, lambda: (self._set_ui_state(running=False), self.status_label.config(text='Done')))

        threading.Thread(target=worker, daemon=True).start()

    # -----------------------------
    # Aircrack-ng Wi-Fi attack
    # -----------------------------
    def start_aircrack(self):
        cap_file = filedialog.askopenfilename(title="Select Handshake File", filetypes=[("Capture files", "*.cap *.pcap")])
        if not cap_file:
            return
        wordlist_file = filedialog.askopenfilename(title="Select Wordlist (optional)", filetypes=[("Text files", "*.txt")])
        self.output.delete(1.0, tk.END)
        self._set_ui_state(running=True)
        self.status_label.config(text='Running Aircrack-ng...')

        def worker():
            cmd = ['aircrack-ng', cap_file]
            if wordlist_file:
                cmd += ['-w', wordlist_file]
            self._append_output(f"Executing: {' '.join(cmd)}\n")
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in process.stdout:
                    self._append_output(line)
                process.wait()
            except Exception as e:
                self._append_output(f"Aircrack-ng error: {e}\n")
            finally:
                self.after(0, lambda: (self._set_ui_state(running=False), self.status_label.config(text='Done')))

        threading.Thread(target=worker, daemon=True).start()


if __name__ == '__main__':
    app = App()
    app.mainloop()
