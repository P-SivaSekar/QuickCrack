# QuickCrack 🔐

QuickCrack is an advanced, colorful, and highly capable password cracking toolkit with both a GUI desktop application and a browser-based Web UI. It supports MD5, SHA1, SHA256 cracking using wordlists or on-demand rainbow tables, as well as WPA2 Wi-Fi handshake verification.

## 🚀 How to Run

### 1. Download the Windows Executable (Easiest)
If you are on Windows, you don't need to install Python.
1. Go to the **[Releases](../../releases)** tab of this repository.
2. Download the latest `QuickCrack-Windows.zip`.
3. Extract it and run `Final.exe`.

### 2. Test in the Browser (Web App)
We have a web application version built with Streamlit. You can deploy it easily to Streamlit Community Cloud or Hugging Face Spaces!

**To run the Web App locally:**
```bash
pip install -r requirements.txt
streamlit run app.py
```

### 3. Run the Desktop App from Source
If you want to run the colorful Tkinter GUI from source:
```bash
pip install -r requirements.txt
python Final.py
```

## 🛠️ Features
* **Modern GUI**: A beautiful, dark-themed Tkinter interface.
* **Streamlit Web UI**: Alternative interface accessible via the browser.
* **Hash Cracking**: Supports MD5, SHA1, and SHA256.
* **WPA2 Cracking**: Built-in Python verifier and Aircrack-ng integration.
* **On-Demand Rainbow Tables**: Load massive rainbow tables into memory only when you need them.

## 💻 Building the Executable
This repository is configured with a GitHub Action that automatically builds the `.exe` file whenever code is pushed. If you want to build it manually:
```bash
pyinstaller --noconfirm --onedir --windowed --add-data "background.png;." Final.py
```
