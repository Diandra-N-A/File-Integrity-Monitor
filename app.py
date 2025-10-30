import streamlit as st
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
import time
import pandas as pd

# Konfigurasi
SECURE_FOLDER = "./secure_files"
HASH_DB_FILE = "hash_db.json"
LOG_FILE = "security.log"

# Pastikan folder dan file ada
os.makedirs(SECURE_FOLDER, exist_ok=True)
Path(LOG_FILE).touch(exist_ok=True)

def calculate_hash(filepath):
    """Menghitung hash SHA256 dari file"""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return None

def log_activity(level, message, filename=""):
    """Mencatat aktivitas ke file log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {level}: {message}"
    if filename:
        log_entry += f' (File: "{filename}")'
    
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry + "\n")
    
    return log_entry

def load_hash_db():
    """Membaca database hash"""
    if os.path.exists(HASH_DB_FILE):
        try:
            with open(HASH_DB_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_hash_db(hash_db):
    """Menyimpan database hash"""
    with open(HASH_DB_FILE, 'w') as f:
        json.dump(hash_db, f, indent=2)

def scan_files():
    """Memindai semua file di folder secure_files"""
    current_files = {}
    if os.path.exists(SECURE_FOLDER):
        for filename in os.listdir(SECURE_FOLDER):
            filepath = os.path.join(SECURE_FOLDER, filename)
            if os.path.isfile(filepath):
                file_hash = calculate_hash(filepath)
                if file_hash:
                    current_files[filename] = {
                        'hash': file_hash,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
                    }
    return current_files

def check_integrity():
    """Memeriksa integritas file dan mendeteksi perubahan"""
    hash_db = load_hash_db()
    current_files = scan_files()
    
    results = {
        'safe': [],
        'modified': [],
        'deleted': [],
        'new': []
    }
    
    # Cek file yang ada sekarang
    for filename, info in current_files.items():
        if filename in hash_db:
            if hash_db[filename]['hash'] == info['hash']:
                results['safe'].append(filename)
                log_activity("INFO", "File verified OK", filename)
            else:
                results['modified'].append(filename)
                log_activity("WARNING", "File integrity failed! Hash mismatch detected", filename)
        else:
            results['new'].append(filename)
            log_activity("ALERT", "Unknown file detected (new file added)", filename)
    
    # Cek file yang hilang
    for filename in hash_db:
        if filename not in current_files:
            results['deleted'].append(filename)
            log_activity("ALERT", "File has been deleted", filename)
    
    # Update database dengan file saat ini
    save_hash_db(current_files)
    
    return results

def parse_logs():
    """Membaca dan menganalisis file log"""
    stats = {
        'total_logs': 0,
        'info': 0,
        'warning': 0,
        'alert': 0,
        'last_anomaly': None,
        'recent_logs': []
    }
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = f.readlines()
            stats['total_logs'] = len(logs)
            
            for log in logs:
                if 'INFO' in log:
                    stats['info'] += 1
                elif 'WARNING' in log:
                    stats['warning'] += 1
                    stats['last_anomaly'] = log.split(']')[0].replace('[', '')
                elif 'ALERT' in log:
                    stats['alert'] += 1
                    stats['last_anomaly'] = log.split(']')[0].replace('[', '')
            
            # Ambil 10 log terakhir
            stats['recent_logs'] = logs[-10:][::-1]
    
    return stats

def create_baseline():
    """Membuat baseline hash untuk semua file saat ini"""
    current_files = scan_files()
    save_hash_db(current_files)
    log_activity("INFO", f"Baseline created for {len(current_files)} files")
    return len(current_files)

def reset_logs():
    """Menghapus semua log dan memulai dari awal"""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log_activity("INFO", "Log system has been reset")
        return True
    except Exception as e:
        return False

# ===== STREAMLIT UI =====
st.set_page_config(page_title="File Integrity Monitor", page_icon="🔒", layout="wide")

st.title("🔒 SussyFile")
st.markdown("**Monitoring & Keamanan Integritas File Real-time**")

# Sidebar
with st.sidebar:
    st.header("⚙️ Kontrol Panel")
    
    if st.button("🔍 Scan Sekarang", type="primary", use_container_width=True):
        with st.spinner("Memindai file..."):
            results = check_integrity()
            st.session_state['scan_results'] = results
            st.session_state['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if st.button("📝 Buat Baseline Baru", use_container_width=True):
        count = create_baseline()
        st.success(f"✅ Baseline dibuat untuk {count} file")
        time.sleep(1)
        st.rerun()
    
    if st.button("🗑️ Reset Log", use_container_width=True):
        if reset_logs():
            st.success("✅ Log berhasil direset")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Gagal mereset log")
    
    st.divider()
    
    st.subheader("📊 Info Sistem")
    if os.path.exists(HASH_DB_FILE):
        hash_db = load_hash_db()
        st.metric("File Terdaftar", len(hash_db))
    else:
        st.warning("⚠️ Belum ada baseline")
    
    if 'last_scan' in st.session_state:
        st.info(f"🕒 Scan terakhir:\n{st.session_state['last_scan']}")

# Tab utama
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📁 File Manager", "📜 Log Activity", "📖 Panduan"])

with tab1:
    st.header("Dashboard Monitoring")
    
    # Statistik
    stats = parse_logs()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("✅ Log INFO", stats['info'])
    with col2:
        st.metric("⚠️ Log WARNING", stats['warning'])
    with col3:
        st.metric("🚨 Log ALERT", stats['alert'])
    with col4:
        st.metric("📝 Total Log", stats['total_logs'])
    
    # Hasil scan terakhir
    if 'scan_results' in st.session_state:
        st.divider()
        st.subheader("🔍 Hasil Scan Terakhir")
        
        results = st.session_state['scan_results']
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.success(f"**✅ File Aman:** {len(results['safe'])}")
            if results['safe']:
                with st.expander("Lihat detail"):
                    for f in results['safe']:
                        st.text(f"• {f}")
            
            st.info(f"**➕ File Baru:** {len(results['new'])}")
            if results['new']:
                with st.expander("Lihat detail"):
                    for f in results['new']:
                        st.text(f"• {f}")
        
        with col2:
            st.warning(f"**⚠️ File Diubah:** {len(results['modified'])}")
            if results['modified']:
                with st.expander("Lihat detail"):
                    for f in results['modified']:
                        st.text(f"• {f}")
            
            st.error(f"**🗑️ File Dihapus:** {len(results['deleted'])}")
            if results['deleted']:
                with st.expander("Lihat detail"):
                    for f in results['deleted']:
                        st.text(f"• {f}")
    else:
        st.info("👆 Klik 'Scan Sekarang' untuk memulai pemantauan")
    
    # Anomali terakhir
    if stats['last_anomaly']:
        st.divider()
        st.warning(f"⏰ **Anomali Terakhir:** {stats['last_anomaly']}")

with tab2:
    st.header("📁 Manajemen File")
    
    current_files = scan_files()
    
    if current_files:
        st.success(f"Ditemukan {len(current_files)} file")
        
        # Buat tabel
        data = []
        for filename, info in current_files.items():
            data.append({
                'Nama File': filename,
                'Ukuran (bytes)': info['size'],
                'Terakhir Diubah': info['modified'],
                'Hash (8 digit)': info['hash'][:8] + "..."
            })
        
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("📭 Belum ada file di folder secure_files/")
        st.info("💡 **Tip:** Tambahkan file ke folder `secure_files/` lalu klik 'Scan Sekarang'")

with tab3:
    st.header("📜 Log Aktivitas")
    
    if stats['recent_logs']:
        # Tombol reset di atas
        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader("🕒 10 Log Terakhir")
        with col2:
            if st.button("🗑️ Hapus Semua Log", type="secondary"):
                if reset_logs():
                    st.success("✅ Log berhasil dihapus")
                    time.sleep(1)
                    st.rerun()
        
        for log in stats['recent_logs']:
            log = log.strip()
            if 'ALERT' in log:
                st.error(log)
            elif 'WARNING' in log:
                st.warning(log)
            else:
                st.info(log)
        
        st.divider()
        
        if st.button("📥 Download Full Log"):
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                st.download_button(
                    label="Download security.log",
                    data=f.read(),
                    file_name="security.log",
                    mime="text/plain"
                )
    else:
        st.info("📭 Belum ada log aktivitas")
        st.caption("Log akan muncul setelah Anda melakukan scan atau membuat baseline")

with tab4:
    st.header("📖 Panduan Penggunaan")
    
    st.markdown("""
    ### 🚀 Cara Menggunakan Sistem
    
    #### 1️⃣ Persiapan Awal
    - Tambahkan file yang ingin dimonitor ke folder `secure_files/`
    - Klik **"Buat Baseline Baru"** untuk mencatat kondisi awal file
    
    #### 2️⃣ Monitoring
    - Klik **"Scan Sekarang"** untuk memeriksa integritas file
    - Sistem akan membandingkan hash file saat ini dengan baseline
    
    #### 3️⃣ Deteksi Perubahan
    Sistem akan mendeteksi:
    - ✅ **File Aman**: Hash cocok dengan baseline
    - ⚠️ **File Diubah**: Hash berbeda (file sudah dimodifikasi)
    - ➕ **File Baru**: File yang tidak ada di baseline
    - 🗑️ **File Dihapus**: File baseline yang hilang
    
    #### 4️⃣ Membaca Log
    - Semua aktivitas tercatat di `security.log`
    - Level: INFO (normal), WARNING (perubahan), ALERT (anomali)
    
    ---
    
    ### 🧪 Cara Testing
    
    **Test 1: File Baru**
    1. Buat baseline
    2. Tambahkan file baru ke `secure_files/`
    3. Scan → akan terdeteksi sebagai "File Baru"
    
    **Test 2: File Diubah**
    1. Edit isi salah satu file
    2. Scan → akan terdeteksi sebagai "File Diubah"
    
    **Test 3: File Dihapus**
    1. Hapus salah satu file
    2. Scan → akan terdeteksi sebagai "File Dihapus"
    
    ---
    
    ### 🔧 Teknologi yang Digunakan
    - **Python**: Bahasa pemrograman
    - **Streamlit**: Framework web app
    - **SHA256**: Algoritma hashing untuk integritas
    - **JSON**: Database hash sederhana
    
    ---
    
    ### 💡 Tips
    - Update baseline setelah perubahan file yang sah
    - Cek log secara berkala untuk anomali
    - Backup `hash_db.json` untuk keamanan
    """)

# Footer
st.divider()
st.caption("Dibuat oleh Andra (5027231004), Faqih (5027231023), Furqon (5027231024), Gallant (5027231037) | Dibuat dengan ❤️ menggunakan Streamlit")
