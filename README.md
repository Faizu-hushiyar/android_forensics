# Android Forensics — SecureOps

An Android forensic suite built with **Streamlit**. Features include device connection via ADB,
15 analysis modules (hidden app detection, dangerous permissions audit, SMS/call review, network
OSINT, SSL inspection, and more), case management, and PDF/Word report export.

---

## 🚀 Deploy on Streamlit Community Cloud

1. **Fork / push** this repository to your GitHub account.
2. Go to [share.streamlit.io](https://share.streamlit.io) and click **New app**.
3. Select your repository, set the branch to `main` (or your branch), and set
   **Main file path** to `app.py`.
4. Under **Advanced settings → Secrets**, add the following (for OTP email):
   ```toml
   OTP_EMAIL = "your_email@gmail.com"
   OTP_PASSWORD = "your_gmail_app_password"
   ```
5. Click **Deploy**.

> **Note:** ADB device features require a local machine with Android SDK Platform-Tools
> installed and a physical device connected. Those features will gracefully degrade
> (show "adb not found") when running on Streamlit Cloud without ADB.

---

## 🖥️ Run locally

```bash
# 1. Clone the repo
git clone https://github.com/Faizu-hushiyar/android_forensics.git
cd android_forensics

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Configure OTP email
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit .streamlit/secrets.toml with your Gmail address and App Password

# 5. Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`.

---

## 📦 Project structure

```
app.py                  # Streamlit entry point
requirements.txt        # Python dependencies
services/
  adb_client.py         # ADB helpers for live device forensics
  android_analysis.py   # Android forensic parsers & heuristics
  case_report.py        # Markdown case-report generator
  report_export.py      # PDF / Word export
  network_osint.py      # WHOIS, DNS, port scan, SSL, traceroute
  db.py                 # SQLite persistence (cases & findings)
assets/
  logo.png
.streamlit/
  config.toml           # Streamlit theme & server settings
  secrets.toml.example  # Credentials template (copy → secrets.toml)
```
