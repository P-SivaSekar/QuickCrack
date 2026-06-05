# QuickCrack 🔐

QuickCrack is an advanced, user-friendly password cracking toolkit. It offers both a simple Web Interface and a Desktop Application. It supports cracking MD5, SHA1, and SHA256 hashes using wordlists and on-demand rainbow tables, as well as WPA2 Wi-Fi handshake verification.

---

## 🌐 Test it Live in the Browser!
You don't need to install anything. I have hosted the application on the cloud so you can test it directly from your phone or computer.

👉 **[Click Here to Test QuickCrack Live](https://quickcrack.streamlit.app/)** 👈

---

## 🧪 How to Test QuickCrack

I have provided sample testing files inside this repository so you can try out the application immediately:
1. **`hashes.txt`**: A file containing various MD5 and SHA hashes.
2. **`wordlist.txt`**: A sample dictionary wordlist containing potential passwords.
3. **`sample_rainbow_table.json`**: A small, sample rainbow table to test the rainbow attack mode.

### Steps to Test:
1. Open the [Live Web App](https://quickcrack.streamlit.app/) or run the Desktop App.
2. Under the **Hash Cracker** tab, upload `hashes.txt` into the "Hash File" box.
3. Upload `wordlist.txt` into the "Wordlist File" box.
4. (Optional) If you want to test Rainbow Table mode, upload `sample_rainbow_table.json`.
5. Click **"Start Cracking"** and watch the results appear on the screen!

---

## 💻 How to Use for Personal Use

If you want to use QuickCrack locally on your own computer, you have two options:

### Option 1: Download the Windows Executable (Easiest)
If you are on Windows, you can download a standalone version of the app. You do **not** need to install Python.
1. Go to the **[Releases](../../releases)** tab of this repository.
2. Download the latest `QuickCrack-Windows.zip`.
3. Extract the downloaded `.zip` file.
4. Double-click `Final.exe` to open the colorful Desktop GUI.

### Option 2: Run from Source (For Developers)
If you are on Mac/Linux or want to run the python scripts directly:

1. Clone or download this repository.
2. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Desktop GUI:
   ```bash
   python Final.py
   ```
4. Or, run the Web UI locally:
   ```bash
   streamlit run app.py
   ```

---

## ⚠️ Copyright and License

**Copyright (c) 2026 P-SivaSekar. All rights reserved.**

This software and its associated documentation are strictly for **personal and educational use only**. 

You may **NOT**:
- Copy, reuse, modify, publish, distribute, or sell copies of this code.
- Reverse engineer the application.
- Use this application for any commercial or malicious purposes. 

Please see the [LICENSE](LICENSE) file for more details.
