import streamlit as st
import bcrypt
import json
import os
import io
import smtplib
import random
import psycopg2 
from email.mime.text import MIMEText
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL CONFIGURATION (GMAIL)
# ─────────────────────────────────────────────────────────────────────────────
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "lowkeyyogesh@gmail.com"
SENDER_PASSWORD = "snreaezamnpybsns"

def send_otp_email(to_email, otp, purpose="registration"):
    """Sends an OTP to the specified email."""
    try:
        subject = "Ink Play - Verify your account" if purpose == "registration" else "Ink Play - Password Reset"
        body = f"Your one-time password (OTP) is: {otp}\n\nPlease enter this code in the app to continue."
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True, "Email sent successfully."
    except Exception as e:
        return False, f"Failed to send email. Error: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# CLOUD DATABASE STORAGE (SUPABASE / POSTGRESQL)
# ─────────────────────────────────────────────────────────────────────────────
MAX_REVISIONS = 30

def get_db_connection():
    """Securely connects to Supabase using your secrets.toml file"""
    return psycopg2.connect(st.secrets["DB_URL"])

def init_db():
    """Initialize the Cloud Database and create tables if they don't exist."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            email TEXT,
            password TEXT,
            created TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scripts (
            username TEXT,
            script_name TEXT,
            content TEXT,
            updated TEXT,
            PRIMARY KEY (username, script_name)
        )
    ''')
    # Postgres uses SERIAL instead of AUTOINCREMENT
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id SERIAL PRIMARY KEY,
            username TEXT,
            script_name TEXT,
            content TEXT,
            saved TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Run the initialization to ensure tables exist in the cloud
init_db()

# ─────────────────────────────────────────────────────────────────────────────
# AUTH & USER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
def check_user_exists(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username=%s", (username,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def register_user(username, email, password):
    if check_user_exists(username):
        return False, "Username already taken."
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO users (username, email, password, created) VALUES (%s, %s, %s, %s)",
              (username, email, hashed, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return True, "Account created."

def login_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=%s", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "User not found."
    if bcrypt.checkpw(password.encode(), row[0].encode()):
        return True, "OK"
    return False, "Incorrect password."

def get_user_email(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE username=%s", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def change_password_with_otp(username, new_pw):
    if not check_user_exists(username):
        return False, "User not found."
    hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET password=%s WHERE username=%s", (hashed, username))
    conn.commit()
    conn.close()
    return True, "Password updated."

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPTS
# ─────────────────────────────────────────────────────────────────────────────
def get_scripts(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT script_name, content, updated FROM scripts WHERE username=%s", (username,))
    rows = c.fetchall()
    conn.close()
    return {row[0]: {"content": row[1], "updated": row[2]} for row in rows}

def save_script(username, name, content):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE scripts SET content=%s, updated=%s WHERE username=%s AND script_name=%s",
              (content, datetime.now().isoformat(), username, name))
    conn.commit()
    conn.close()

def new_script(username, name):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM scripts WHERE username=%s AND script_name=%s", (username, name))
    if c.fetchone():
        conn.close()
        return False
    c.execute("INSERT INTO scripts (username, script_name, content, updated) VALUES (%s, %s, %s, %s)",
              (username, name, "", datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return True

def delete_script(username, name):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scripts WHERE username=%s AND script_name=%s", (username, name))
    c.execute("DELETE FROM history WHERE username=%s AND script_name=%s", (username, name))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# REVISION HISTORY
# ─────────────────────────────────────────────────────────────────────────────
def push_revision(username, script_name, content):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT content FROM history WHERE username=%s AND script_name=%s ORDER BY id DESC LIMIT 1", (username, script_name))
    row = c.fetchone()
    if row and row[0] == content:
        conn.close()
        return

    c.execute("INSERT INTO history (username, script_name, content, saved) VALUES (%s, %s, %s, %s)",
              (username, script_name, content, datetime.now().isoformat()))
    
    # Enforce MAX_REVISIONS dynamically
    c.execute("""
        DELETE FROM history WHERE id NOT IN (
            SELECT id FROM history WHERE username=%s AND script_name=%s ORDER BY id DESC LIMIT %s
        ) AND username=%s AND script_name=%s
    """, (username, script_name, MAX_REVISIONS, username, script_name))
    
    conn.commit()
    conn.close()

def get_revisions(username, script_name):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT content, saved FROM history WHERE username=%s AND script_name=%s ORDER BY id ASC", (username, script_name))
    rows = c.fetchall()
    conn.close()
    return [{"content": row[0], "saved": row[1]} for row in rows]

def restore_revision(username, script_name, idx):
    revs = get_revisions(username, script_name)
    if 0 <= idx < len(revs):
        content = revs[idx]["content"]
        save_script(username, script_name, content)
        return content
    return None

def clear_all_history(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM history WHERE username=%s", (username,))
    conn.commit()
    conn.close()

def clear_script_history(username, script_name):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM history WHERE username=%s AND script_name=%s", (username, script_name))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# PDF EXPORT
# ─────────────────────────────────────────────────────────────────────────────
def build_pdf(username, script_name, content):
    buf = io.BytesIO()
    c   = canvas.Canvas(buf, pagesize=letter)
    W, H = letter
    ML, MR, MT, MB = 1.5*inch, 1.0*inch, 1.0*inch, 1.0*inch
    usable = W - ML - MR
    LH = 13
    y  = H - MT
    pnum = 1

    def footer():
        c.setFont("Courier", 9)
        c.setFillColorRGB(0, 0, 0)
        c.drawRightString(W - MR, MB * 0.45, str(pnum))

    def next_page():
        nonlocal y, pnum
        footer(); c.showPage(); pnum += 1; y = H - MT

    def need(n=1):
        nonlocal y
        if y - LH * n < MB:
            next_page()

    lines = content.split("\n")
    i = 0
    while i < len(lines):
        s  = lines[i].strip()
        if not s:
            y -= LH * 0.5; i += 1; continue
        up = s.upper()

        if up.startswith("INT.") or up.startswith("EXT."):
            need(2); y -= LH * 0.6
            c.setFont("Courier-Bold", 11)
            c.setFillColorRGB(0,0,0)
            c.drawString(ML, y, up)
            y -= LH * 1.2; i += 1; continue

        if s == s.upper() and s.endswith(":") and len(s) > 2:
            need(3); y -= LH * 0.5
            c.setFont("Courier-Bold", 11)
            c.drawCentredString(W/2, y, s[:-1])
            y -= LH; i += 1
            while i < len(lines):
                d = lines[i].strip()
                if not d: break
                if d.upper().startswith("INT.") or d.upper().startswith("EXT."): break
                if d == d.upper() and d.endswith(":") and len(d) > 2: break
                c.setFont("Courier", 11)
                words, b2, mw = d.split(), "", usable * 0.60
                for w in words:
                    t = (b2 + " " + w).strip()
                    if c.stringWidth(t, "Courier", 11) <= mw: b2 = t
                    else:
                        need(); c.drawCentredString(W/2, y, b2); y -= LH; b2 = w
                if b2: need(); c.drawCentredString(W/2, y, b2); y -= LH
                i += 1
            continue

        c.setFont("Courier", 11)
        words, b2 = s.split(), ""
        for w in words:
            t = (b2 + " " + w).strip()
            if c.stringWidth(t, "Courier", 11) <= usable: b2 = t
            else:
                need(); c.drawString(ML, y, b2); y -= LH; b2 = w
        if b2: need(); c.drawString(ML, y, b2); y -= LH
        i += 1

    footer(); c.save(); buf.seek(0)
    return buf

# ─────────────────────────────────────────────────────────────────────────────
# SCREENPLAY UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def estimate_pages(content):
    lines = [l for l in content.split("\n") if l.strip()]
    return max(1, round(len(lines) / 55 * 10) / 10)

def extract_scenes(content):
    scenes = []
    for i, line in enumerate(content.split("\n")):
        s = line.strip().upper()
        if s.startswith("INT.") or s.startswith("EXT."):
            scenes.append((i + 1, line.strip()))
    return scenes

def word_count(content):
    return len(content.split())

# ─────────────────────────────────────────────────────────────────────────────
# SESSION
# ─────────────────────────────────────────────────────────────────────────────
def init_session():
    for k, v in [
        ("logged_in", False), ("username", ""), ("script", None),
        ("dark_mode", True),  ("auth_mode", "login"),
        ("msg", ""), ("msg_type", ""),
        ("focus_mode", False), ("show_history", False), ("jump_scene", None),
        ("page", "dashboard"), 
        ("view_mode", "Grid"), 
        ("select_mode", False), 
        ("text_color", ""), 
        ("page_color", ""), 
        ("reg_step", 1), ("reg_data", {}), 
        ("pw_step", 1), ("pw_data", {})
    ]:
        if k not in st.session_state:
            st.session_state[k] = v

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────────────────────────────────────
def global_css(dark):
    BG  = "#0a0a0a" if dark else "#fafafa"
    FG  = "#f0f0f0" if dark else "#0a0a0a"
    SUB = "#555555" if dark else "#aaaaaa"
    BRD = "#2a2a2a" if dark else "#dddddd"
    INP = "#141414" if dark else "#ffffff"

    st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IM+Fell+English:ital@0;1&display=swap');

*, *::before, *::after {{ box-sizing: border-box !important; }}

html, body {{
    margin: 0 !important; padding: 0 !important;
    background: {BG} !important;
    color: {FG} !important;
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif !important;
    font-weight: 700 !important;
    -webkit-font-smoothing: antialiased !important;
}}

.stApp, [data-testid="stAppViewContainer"], [data-testid="stAppViewBlockContainer"], section.main {{ background: {BG} !important; }}
.block-container {{
    background: {BG} !important;
    padding: 2rem 2.5rem 2rem 2.5rem !important;
    max-width: 100% !important;
}}

[data-testid="stSidebar"] {{ display: none !important; }}

p, span, div, label, small, caption, li, td, th, h1, h2, h3, h4, h5, h6 {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif !important;
    font-weight: 700 !important;
    color: {FG} !important;
}}

/* TEXT INPUTS (Hamburger/Pill Shape - FIXED Inner Conflicts) */
.stTextInput label {{ display: none !important; }}

/* Remove default streamlit wrapper backgrounds so they don't block the curve */
.stTextInput > div > div {{ background: transparent !important; border: none !important; }}

/* Target the core baseweb input and apply the actual pill shape */
.stTextInput div[data-baseweb="input"] {{
    background-color: {INP} !important;
    border: 1px solid {BRD} !important;
    border-radius: 24px !important;
    overflow: hidden !important;
}}
.stTextInput div[data-baseweb="input"]:focus-within {{
    border-color: {FG} !important;
}}

/* Force every internal container (like the password eye block) to be completely transparent */
.stTextInput div[data-baseweb="input"] * {{
    background-color: transparent !important;
    border: none !important;
}}

/* Style the actual text typed by the user */
.stTextInput div[data-baseweb="input"] input {{
    color: {FG} !important;
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif !important;
    font-size: 13px !important;
    padding: 12px 18px !important;
    caret-color: {FG} !important;
}}

/* LARGE TEXT AREA (Script Editor) */
textarea {{
    background: {INP} !important; color: {FG} !important; border: 1px solid {BRD} !important;
    border-radius: 4px !important; font-family: 'Courier New', Courier, monospace !important;
    font-size: 14px !important; line-height: 1.7 !important; padding: 16px !important;
    outline: none !important; resize: vertical !important;
}}
textarea:focus {{ border-color: {FG} !important; }}
.stTextArea > div > div > textarea {{
    background: {INP} !important; color: {FG} !important; border: 1px solid {BRD} !important;
    border-radius: 4px !important; font-family: 'Courier New', Courier, monospace !important;
    font-size: 14px !important; line-height: 1.7 !important; outline: none !important;
}}
.stTextArea label {{ display: none !important; }}

/* PREVENT TEXT WRAPPING & FORCE BORDERS TO WRAP AROUND TEXT */
.stButton > button, [data-testid="stDownloadButton"] > button {{
    white-space: nowrap !important;
    background: transparent !important; color: {FG} !important; border: 1px solid {BRD} !important;
    border-radius: 24px !important;
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif !important;
    font-size: 10px !important; font-weight: 600 !important; letter-spacing: .08em !important;
    padding: 8px 12px !important; cursor: pointer !important; transition: all .2s ease !important;
    width: 100% !important; 
    min-width: max-content !important; 
    text-transform: uppercase !important;
}}
.stButton > button:hover, [data-testid="stDownloadButton"] > button:hover {{
    background: {FG} !important; color: {BG} !important; border-color: {FG} !important;
}}

/* Checkbox specific styles for dashboard bulk delete */
[data-testid="stCheckbox"] label p {{ font-size: 13px !important; color: {FG} !important; font-weight: 700 !important; margin: 0 !important; padding: 0 0 0 4px !important; }}

[data-testid="stSelectbox"] > div > div {{
    background: {INP} !important; color: {FG} !important; border: 1px solid {BRD} !important;
    border-radius: 2px !important; font-size: 12px !important;
}}
[data-testid="stSelectbox"] svg {{ fill: {FG} !important; stroke: {FG} !important; }}
[data-testid="stSelectbox"] span {{ color: {FG} !important; }}
[data-testid="stSelectbox"] label {{ display: none !important; }}

[data-baseweb="popover"] > div {{ background: {INP} !important; border: 1px solid {BRD} !important; border-radius: 8px !important; padding: 1rem !important; }}
[data-baseweb="menu"] li, [data-baseweb="menu"] {{ background: {INP} !important; color: {FG} !important; font-size: 12px !important; }}
[data-baseweb="menu"] li:hover {{ background: {FG} !important; color: {BG} !important; }}

[data-testid="stTabs"] [role="tablist"] {{ border-bottom: 1px solid {BRD} !important; gap: 0 !important; background: transparent !important; }}
[data-testid="stTabs"] button[role="tab"] {{
    background: transparent !important; color: {SUB} !important; border: none !important;
    border-bottom: 2px solid transparent !important; font-size: 11px !important;
    letter-spacing: .14em !important; padding: 10px 20px !important; font-weight: 400 !important; margin-bottom: -1px !important;
}}
[data-testid="stTabs"] button[role="tab"]:hover {{ color: {FG} !important; background: transparent !important; }}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {{ color: {FG} !important; border-bottom: 2px solid {FG} !important; font-weight: 700 !important; }}

[data-testid="stRadio"] {{ display: flex !important; justify-content: center !important; }}
[data-testid="stRadio"] > div {{ display: flex !important; flex-direction: row !important; gap: 24px !important; }}
[data-testid="stRadio"] label {{ font-size: 11px !important; letter-spacing: .14em !important; color: {SUB} !important; cursor: pointer !important; text-transform: uppercase !important; }}
[data-testid="stRadio"] label:has(input:checked) {{ color: {FG} !important; }}
[data-testid="stRadio"] label > div:first-child {{ display: none !important; }}

[data-testid="stAlert"] {{ background: transparent !important; border: 1px solid {BRD} !important; border-radius: 2px !important; }}
[data-testid="stAlert"] p, [data-testid="stAlert"] span {{ color: {FG} !important; font-size: 12px !important; }}
[data-testid="stAlert"] svg, .stException {{ display: none !important; }}

hr {{ border: none !important; border-top: 1px solid {BRD} !important; margin: 14px 0 !important; }}
::-webkit-scrollbar {{ width: 4px; height: 4px; }}
::-webkit-scrollbar-track {{ background: {BG}; }}
::-webkit-scrollbar-thumb {{ background: {BRD}; border-radius: 2px; }}

#MainMenu, header, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"], [data-testid="stHeader"], .stDeployButton {{ display: none !important; visibility: hidden !important; }}

.focus-mode-active .block-container {{ max-width: 780px !important; margin: 0 auto !important; padding: 3rem 2rem !important; }}
*:focus {{ outline: none !important; box-shadow: none !important; }}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# AUTH PAGE
# ─────────────────────────────────────────────────────────────────────────────
def page_auth():
    dark = st.session_state.dark_mode
    BG   = "#0a0a0a" if dark else "#fafafa"
    FG   = "#f0f0f0" if dark else "#0a0a0a"
    SUB  = "#555555" if dark else "#aaaaaa"
    BRD  = "#2a2a2a" if dark else "#dddddd"

    st.markdown(f"""
<style>
.block-container {{ display: flex !important; align-items: center !important; justify-content: center !important; min-height: 100vh !important; padding: 0 !important; max-width: 400px !important; margin: 0 auto !important; }}
section.main > div {{ display: flex !important; align-items: center !important; min-height: 100vh !important; }}
</style>
""", unsafe_allow_html=True)

    st.markdown(f"""
<div style="text-align:center; margin-bottom: 40px;">
    <div style="font-size: 1.9rem; letter-spacing: .28em; font-weight: 900; color: {FG}; margin-bottom: 6px;">INK PLAY</div>
    <div style="font-size: .62rem; letter-spacing: .32em; color: {SUB};">SCREENPLAY PLATFORM</div>
    <div style="width: 32px; height: 1px; background: {BRD}; margin: 18px auto 0 auto;"></div>
</div>
""", unsafe_allow_html=True)

    if st.session_state.reg_step == 2:
        st.markdown(f"<p style='font-size:12px;color:{SUB};text-align:center;'>We sent an OTP to {st.session_state.reg_data.get('email')}.</p>", unsafe_allow_html=True)
        user_otp = st.text_input("ENTER OTP", placeholder="6-digit OTP", key="reg_otp")
        
        st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
        
        if st.session_state.msg:
            st.markdown(f"<p style='font-size:11px;letter-spacing:.1em; color:{FG}; text-align:center; margin:0 0 10px 0;'>{st.session_state.msg}</p>", unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("CANCEL", use_container_width=True):
                st.session_state.reg_step = 1
                st.session_state.reg_data = {}
                st.session_state.msg = ""
                st.rerun()
        with col2:
            if st.button("VERIFY", use_container_width=True):
                # Pull directly from Streamlit's deep memory
                entered_otp = str(st.session_state.reg_otp).strip()
                real_otp = str(st.session_state.reg_data.get("otp")).strip()
                
                if entered_otp == real_otp:
                    d = st.session_state.reg_data
                    ok, msg = register_user(d["user"], d["email"], d["pw"])
                    if ok:
                        # THE FIX: Auto-log the user in and teleport to the dashboard!
                        st.session_state.logged_in = True
                        st.session_state.username = d["user"]
                        st.session_state.page = "dashboard"
                        
                        # Clean up the background data
                        st.session_state.reg_step = 1
                        st.session_state.reg_data = {}
                        st.session_state.msg = ""
                    else:
                        st.session_state.msg = msg
                else:
                    st.session_state.msg = "Invalid OTP. Please try again."
                st.rerun()
        return

    mode = st.radio("", ["Login", "Register"], horizontal=True, label_visibility="collapsed", key="auth_mode_radio")
    st.markdown("<div style='height: 18px'></div>", unsafe_allow_html=True)

    user = st.text_input("USERNAME", placeholder="Username", key="a_user")
    
    if mode == "Register":
        email = st.text_input("EMAIL", placeholder="Email address", key="a_email")
    else:
        email = None
        
    pw = st.text_input("PASSWORD", placeholder="Password", type="password", key="a_pw")
    st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)

    if st.session_state.msg:
        st.markdown(f"<p style='font-size:11px;letter-spacing:.1em; color:{FG}; text-align:center; margin:0 0 10px 0;'>{st.session_state.msg}</p>", unsafe_allow_html=True)

    btn_label = "ENTER" if mode == "Login" else "SEND OTP"
    
    if st.button(btn_label, use_container_width=True, key="auth_btn"):
        st.session_state.msg = ""
        u = user.strip()
        
        if mode == "Login":
            if not u or not pw:
                st.session_state.msg = "Please fill in both fields."
                st.rerun()
            ok, msg = login_user(u, pw)
            if ok:
                st.session_state.logged_in = True
                st.session_state.username  = u
                st.session_state.msg       = ""
                st.session_state.page      = "dashboard"
                st.rerun()
            else:
                st.session_state.msg = msg
                st.rerun()
                
        else:
            e = email.strip()
            if not u or not pw or not e:
                st.session_state.msg = "Please fill in all fields."
                st.rerun()
            if len(u) < 3:
                st.session_state.msg = "Username must be 3+ characters."
                st.rerun()
            if len(pw) < 6:
                st.session_state.msg = "Password must be 6+ characters."
                st.rerun()
            if check_user_exists(u):
                st.session_state.msg = "Username already taken."
                st.rerun()

            st.session_state.msg = "Sending OTP..."
            generated_otp = str(random.randint(100000, 999999))
            
            success, err_msg = send_otp_email(e, generated_otp, "registration")
            if success:
                st.session_state.reg_step = 2
                st.session_state.reg_data = {"user": u, "email": e, "pw": pw, "otp": generated_otp}
                st.session_state.msg = ""
            else:
                st.session_state.msg = err_msg
            st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD PAGE
# ─────────────────────────────────────────────────────────────────────────────
def page_dashboard():
    dark     = st.session_state.dark_mode
    username = st.session_state.username
    BG       = "#0a0a0a" if dark else "#fafafa"
    FG       = "#f0f0f0" if dark else "#0a0a0a"
    SUB      = "#555555" if dark else "#aaaaaa"
    BRD      = "#2a2a2a" if dark else "#dddddd"
    INP      = "#141414" if dark else "#ffffff"

    st.markdown("""<style>.block-container { max-width: 900px !important; margin: 0 auto !important; padding: 2rem !important; }</style>""", unsafe_allow_html=True)

    # ── Header ──
    col_brand, col_spacer, col_settings = st.columns([4, 1, 1.5])
    with col_brand:
        st.markdown(f"<div style='font-size:1.5rem; font-weight:900; color:{FG}; letter-spacing:.2em;'>INK PLAY</div>", unsafe_allow_html=True)
        st.markdown(f"<div style='font-size:0.6rem; color:{SUB}; letter-spacing:.1em; margin-bottom: 20px;'>DASHBOARD • {username.upper()}</div>", unsafe_allow_html=True)
    with col_settings:
        if st.button("⚙️ SETTINGS", use_container_width=True):
            st.session_state.page = "settings"
            st.rerun()
            
    st.markdown("<hr style='margin: 0 0 20px 0;'>", unsafe_allow_html=True)
    
    # ── Create New Script ──
    st.markdown(f"<div style='font-size:10px; letter-spacing:.1em; color:{SUB}; margin-bottom:8px;'>CREATE NEW SCRIPT</div>", unsafe_allow_html=True)
    col_inp, col_btn = st.columns([4, 1])
    with col_inp:
        nname = st.text_input("N", placeholder="Enter your new script title here...", key="dash_new_name", label_visibility="collapsed")
    with col_btn:
        if st.button("➕ CREATE", use_container_width=True):
            n = nname.strip()
            if n:
                if new_script(username, n):
                    st.session_state.script = n
                    st.session_state.page = "app"
                    st.rerun()
                else:
                    st.toast("A script with that name already exists.", icon="⚠️")
                    
    st.markdown("<div style='height: 30px'></div>", unsafe_allow_html=True)
    
    # ── Scripts Section Header, Select Mode & View Toggle ──
    col_title, col_sel, col_tgl = st.columns([3, 1.5, 1.5])
    with col_title:
        st.markdown(f"<div style='font-size:14px; font-weight:700; color:{FG}; letter-spacing:.1em; padding-top: 10px;'>YOUR SCRIPTS</div>", unsafe_allow_html=True)
    with col_sel:
        if st.session_state.select_mode:
            if st.button("CANCEL", use_container_width=True):
                st.session_state.select_mode = False
                st.rerun()
        else:
            if st.button("SELECT & DELETE", use_container_width=True):
                st.session_state.select_mode = True
                st.rerun()
    with col_tgl:
        mode = st.radio("View", ["Grid", "List"], horizontal=True, label_visibility="collapsed", index=0 if st.session_state.view_mode=="Grid" else 1)
        if mode != st.session_state.view_mode:
            st.session_state.view_mode = mode
            st.rerun()

    st.markdown("<hr style='margin: 10px 0 20px 0;'>", unsafe_allow_html=True)
    
    scripts = get_scripts(username)
    if not scripts:
        st.markdown(f"<div style='text-align:center; padding: 40px; color:{SUB}; font-size:12px; letter-spacing:.1em;'>NO SCRIPTS FOUND. CREATE ONE ABOVE TO START WRITING.</div>", unsafe_allow_html=True)
        return

    # ── Delete Selected Button (Only visible in Select Mode) ──
    if st.session_state.select_mode:
        col_del, _ = st.columns([2, 4])
        with col_del:
            if st.button("🗑️ DELETE SELECTED", use_container_width=True):
                for sname in list(scripts.keys()):
                    if st.session_state.get(f"chk_{sname}"):
                        delete_script(username, sname)
                st.session_state.select_mode = False
                st.rerun()
        st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
        
    # ── Display Scripts ──
    if st.session_state.view_mode == "Grid":
        # Icon / Grid View
        cols = st.columns(4)
        for idx, (sname, data) in enumerate(scripts.items()):
            upd = data.get("updated", "")
            ts  = datetime.fromisoformat(upd).strftime("%b %d") if upd else ""
            with cols[idx % 4]:
                if st.session_state.select_mode:
                    st.markdown(f"<div style='padding: 10px; background:{INP}; border: 1px solid {BRD}; border-radius: 4px;'>", unsafe_allow_html=True)
                    st.checkbox(f"🎬 {sname}", key=f"chk_{sname}")
                    st.markdown(f"<div style='font-size:10px; color:{SUB}; margin-top: 4px;'>Last edit: {ts}</div></div>", unsafe_allow_html=True)
                else:
                    if st.button(f"🎬 {sname}\n\nLast edit: {ts}", key=f"grid_{sname}", use_container_width=True):
                        st.session_state.script = sname
                        st.session_state.page = "app"
                        st.rerun()
    else:
        # Bar / List View
        for sname, data in scripts.items():
            upd = data.get("updated", "")
            ts  = datetime.fromisoformat(upd).strftime("%b %d, %Y - %H:%M") if upd else ""
            
            col_n, col_d, col_b = st.columns([4, 2, 1])
            with col_n:
                if st.session_state.select_mode:
                    st.checkbox(f"🎬 {sname}", key=f"chk_{sname}")
                else:
                    st.markdown(f"<div style='padding-top:10px; font-weight:700; font-size:14px; color:{FG};'>🎬 {sname}</div>", unsafe_allow_html=True)
            with col_d:
                st.markdown(f"<div style='padding-top:12px; font-size:12px; color:{SUB};'>{ts}</div>", unsafe_allow_html=True)
            with col_b:
                if not st.session_state.select_mode:
                    if st.button("OPEN", key=f"list_{sname}", use_container_width=True):
                        st.session_state.script = sname
                        st.session_state.page = "app"
                        st.rerun()
            st.markdown(f"<hr style='border-top:1px solid {BRD}; margin: 8px 0;'>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN APP (EDITOR)
# ─────────────────────────────────────────────────────────────────────────────
def page_app():
    dark     = st.session_state.dark_mode
    username = st.session_state.username
    BG       = "#0a0a0a" if dark else "#fafafa"
    FG       = st.session_state.text_color  if st.session_state.text_color  else ("#f0f0f0" if dark else "#0a0a0a")
    SUB      = "#555555" if dark else "#aaaaaa"
    BRD      = "#2a2a2a" if dark else "#dddddd"
    INP      = st.session_state.page_color  if st.session_state.page_color  else ("#141414" if dark else "#ffffff")

    if st.session_state.focus_mode:
        st.markdown("""<style>.block-container { max-width: 820px !important; margin: 0 auto !important; padding: 2rem !important; }</style>""", unsafe_allow_html=True)

    custom_css = ""
    if st.session_state.text_color: custom_css += f"textarea {{ color: {st.session_state.text_color} !important; }}\n"
    if st.session_state.page_color: custom_css += f"textarea {{ background: {st.session_state.page_color} !important; }}\n"
    if custom_css: st.markdown(f"<style>{custom_css}</style>", unsafe_allow_html=True)

    scripts = get_scripts(username)

    if not st.session_state.script or st.session_state.script not in scripts:
        st.session_state.page = "dashboard"
        st.rerun()

    sname   = st.session_state.script
    sdata   = scripts[sname]
    content = sdata.get("content", "")

    # ── GLOBAL TOP NAVIGATION ROW ─────────────────────────────────────────────
    col_back, col_spc1, col_brand, col_spc2, col_menu = st.columns([1.5, 0.5, 4, 0.5, 1.5])
    
    with col_back:
        if st.button("← DASHBOARD", use_container_width=True):
            st.session_state.page = "dashboard"
            st.rerun()

    with col_spc1:
        st.empty()

    with col_brand:
        st.markdown(f"<div style='font-size:1.2rem; font-weight:900; color:{FG}; letter-spacing:.2em; padding-top:4px;'>INK PLAY</div>", unsafe_allow_html=True)
        st.markdown(f"<div style='font-size:0.5rem; color:{SUB}; letter-spacing:.1em;'>{username.upper()} • {sname.upper()}</div>", unsafe_allow_html=True)

    with col_spc2:
        st.empty()

    with col_menu:
        if st.button("⚙️ SETTINGS", use_container_width=True):
            st.session_state.page = "settings"
            st.rerun()

    st.markdown("<hr style='margin: 8px 0 16px 0 !important;'>", unsafe_allow_html=True)

    # ── DOCUMENT ACTIONS ROW ──────────────────────────────────────────────────
    col_t, col_stats, col_cloud, col_pdf, col_focus, col_del = st.columns([1.5, 0.5, 1.5, 1.5, 1.5, 1.5])
    
    with col_t:
        upd = sdata.get("updated", "")
        ts  = datetime.fromisoformat(upd).strftime("%b %d, %H:%M") if upd else ""
        st.markdown(f"""
        <div style="margin-bottom: 4px; padding-top:2px;">
            <span style="font-weight:700; font-size:1.1rem; letter-spacing:.14em; color:{FG};">{sname.upper()}</span>
            {"<span style='font-size:.65rem; letter-spacing:.1em; color:" + SUB + "; margin-left:14px;'>SAVED " + ts + "</span>" if ts else ""}
        </div>
        """, unsafe_allow_html=True)

    with col_stats:
        pages = estimate_pages(content) if content.strip() else 0
        st.markdown(f"<div style='text-align:center; padding-top:6px;'><span style='font-size:.6rem; letter-spacing:.14em; color:{SUB};'>PG.</span> <span style='font-size:1.1rem; font-weight:700; color:{FG};'>{pages}</span></div>", unsafe_allow_html=True)

    with col_cloud:
        if st.button("CLOUD SYNC", use_container_width=True, key="cloud_btn"):
            save_script(username, sname, content)
            st.toast("Script successfully synced to cloud.", icon="☁️")

    with col_pdf:
        pdf_data = build_pdf(username, sname, content)
        safe_fn  = "".join(c if c.isalnum() or c in "-_" else "_" for c in f"{username}_{sname}")
        st.download_button("EXPORT PDF", data=pdf_data, file_name=f"{safe_fn}.pdf", mime="application/pdf", use_container_width=True, key="pdf_btn")

    with col_focus:
        focus_label = "EXIT FOCUS" if st.session_state.focus_mode else "FOCUS"
        if st.button(focus_label, use_container_width=True, key="focus_btn"):
            st.session_state.focus_mode = not st.session_state.focus_mode
            st.rerun()

    with col_del:
        if st.button("DELETE", use_container_width=True, key="del_btn"):
            delete_script(username, sname)
            st.session_state.script = None
            st.session_state.page = "dashboard"
            st.rerun()

    st.markdown("<hr style='margin: 8px 0 0 0 !important;'>", unsafe_allow_html=True)

    # ── TABS ──────────────────────────────────────────────────────────────────
    tab_w, tab_scenes, tab_hist, tab_p = st.tabs(["Write", "Scenes", "History", "Preview"])

    with tab_w:
        st.markdown(f"<div style='font-size:.65rem; letter-spacing:.1em; color:{SUB}; margin-bottom:10px;'>INT. / EXT. → scene heading  ·  ALL CAPS: → character cue  ·  autosaves</div>", unsafe_allow_html=True)
        new_text = st.text_area(
            "W", value=content, height=620, label_visibility="collapsed", key=f"ta_{sname}",
            placeholder="INT. APARTMENT — NIGHT\n\nThe room is bare. A single lamp flickers.\n\nELENA:\nI've been waiting for this moment.\n"
        )
        if new_text != content:
            save_script(username, sname, new_text)
            push_revision(username, sname, new_text)

    with tab_scenes:
        scenes = extract_scenes(content)
        if scenes:
            st.markdown(f"<div style='font-size:.6rem;letter-spacing:.14em;color:{SUB};margin-bottom:14px;'>{len(scenes)} SCENE{'S' if len(scenes)!=1 else ''} · {estimate_pages(content)} PAGES · {word_count(content)} WORDS</div>", unsafe_allow_html=True)
            for ln, heading in scenes:
                col_ln, col_heading = st.columns([1, 6])
                with col_ln: st.markdown(f"<div style='font-size:.65rem;color:{SUB};padding-top:3px;letter-spacing:.06em;'>L{ln}</div>", unsafe_allow_html=True)
                with col_heading: st.markdown(f"<div style='font-size:.8rem;font-weight:700;letter-spacing:.08em;color:{FG};padding:4px 0;border-bottom:1px solid {BRD};'>{heading}</div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='font-size:.75rem;color:{SUB};text-align:center;margin-top:60px;letter-spacing:.14em;'>NO SCENES YET.<br><br>START A LINE WITH INT. OR EXT. TO CREATE ONE.</p>", unsafe_allow_html=True)

    with tab_hist:
        revs = get_revisions(username, sname)
        if revs:
            st.markdown(f"<div style='font-size:.6rem;letter-spacing:.14em;color:{SUB};margin-bottom:14px;'>{len(revs)} REVISION{'S' if len(revs)!=1 else ''} SAVED (MAX {MAX_REVISIONS})</div>", unsafe_allow_html=True)
            for idx, rev in reversed(list(enumerate(revs))):
                ts_rev = datetime.fromisoformat(rev["saved"]).strftime("%b %d, %H:%M:%S") if "T" in rev["saved"] else rev["saved"]
                preview_text = rev["content"][:120].replace("\n", " ")
                col_info, col_btn = st.columns([5, 1])
                with col_info:
                    st.markdown(f"<div style='padding:8px 0;border-bottom:1px solid {BRD};'><div style='font-size:.65rem;letter-spacing:.1em;color:{SUB};margin-bottom:3px;'>{ts_rev}</div><div style='font-size:.75rem;color:{FG};opacity:.7;'>{preview_text}…</div></div>", unsafe_allow_html=True)
                with col_btn:
                    if st.button("RESTORE", key=f"rev_{idx}", use_container_width=True):
                        restored = restore_revision(username, sname, idx)
                        if restored:
                            st.session_state[f"ta_{sname}"] = restored
                            st.rerun()
        else:
            st.markdown(f"<p style='font-size:.75rem;color:{SUB};text-align:center;margin-top:60px;letter-spacing:.14em;'>NO REVISIONS YET.</p>", unsafe_allow_html=True)

    with tab_p:
        if content.strip():
            lines = content.split("\n")
            html_out = []
            i = 0
            while i < len(lines):
                s  = lines[i].strip()
                up = s.upper()

                if not s: html_out.append("<div style='height:10px'></div>"); i += 1; continue

                if up.startswith("INT.") or up.startswith("EXT."):
                    html_out.append(f"<p style='font-weight:700; font-size:13px; text-transform:uppercase; letter-spacing:.04em; margin:20px 0 3px 0; color:{FG};'>{up}</p>")
                    i += 1; continue

                if s == s.upper() and s.endswith(":") and len(s) > 2:
                    html_out.append(f"<p style='font-weight:700; font-size:13px; text-align:center; margin:18px 0 1px 0; color:{FG};'>{s[:-1]}</p>")
                    i += 1
                    while i < len(lines):
                        d = lines[i].strip()
                        if not d or d.upper().startswith("INT.") or d.upper().startswith("EXT.") or (d == d.upper() and d.endswith(":") and len(d) > 2): break
                        html_out.append(f"<p style='font-weight:700; font-size:13px; text-align:center; margin:1px 15% 1px 15%; color:{FG};'>{d}</p>")
                        i += 1
                    continue

                html_out.append(f"<p style='font-weight:700; font-size:13px; margin:2px 0; color:{FG};'>{s}</p>")
                i += 1

            st.markdown(f"<div style='background:{INP}; border:1px solid {BRD}; padding:32px 44px; max-height:580px; overflow-y:auto; line-height:1.75;'>{''.join(html_out)}</div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='font-size:.75rem; color:{SUB}; text-align:center; margin-top:80px; letter-spacing:.14em;'>NOTHING TO PREVIEW YET.</p>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS PAGE
# ─────────────────────────────────────────────────────────────────────────────
def page_settings():
    dark     = st.session_state.dark_mode
    username = st.session_state.username
    BG  = "#0a0a0a" if dark else "#fafafa"
    FG  = "#f0f0f0" if dark else "#0a0a0a"
    SUB = "#555555" if dark else "#aaaaaa"
    BRD = "#2a2a2a" if dark else "#dddddd"
    INP = "#141414" if dark else "#ffffff"

    st.markdown("""<style>.block-container { max-width: 560px !important; margin: 0 auto !important; padding: 3rem 2rem !important; }</style>""", unsafe_allow_html=True)

    col_back, col_spacer, col_title = st.columns([1.5, 0.5, 4])
    with col_back:
        if st.button("← BACK", use_container_width=True, key="settings_back"):
            st.session_state.page = "dashboard"
            st.rerun()
    with col_spacer:
        st.empty()
    with col_title:
        st.markdown(f"<div style='font-size:1.1rem;letter-spacing:.22em;font-weight:700;color:{FG};padding-top:8px;'>SETTINGS</div>", unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)

    st.markdown(f"<div style='font-size:.6rem;letter-spacing:.2em;color:{SUB};margin-bottom:14px;'>APPEARANCE</div>", unsafe_allow_html=True)
    if st.button("Switch to Light Mode" if dark else "Switch to Dark Mode", use_container_width=True, key="settings_theme"):
        st.session_state.dark_mode = not dark
        st.rerun()

    st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
    st.markdown(f"<div style='font-size:.6rem;letter-spacing:.16em;color:{SUB};margin-bottom:8px;'>SCREENPLAY TEXT COLOR</div>", unsafe_allow_html=True)
    col_tc, col_tc_reset = st.columns([3, 1])
    with col_tc:
        tc_default = st.session_state.text_color if st.session_state.text_color else ("#f0f0f0" if dark else "#0a0a0a")
        new_tc = st.color_picker("Text color", value=tc_default, key="cp_text", label_visibility="collapsed")
        if new_tc != st.session_state.text_color:
            st.session_state.text_color = new_tc
            st.rerun()
    with col_tc_reset:
        if st.button("Reset", key="tc_reset", use_container_width=True):
            st.session_state.text_color = ""
            st.rerun()

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    st.markdown(f"<div style='font-size:.6rem;letter-spacing:.16em;color:{SUB};margin-bottom:8px;'>SCREENPLAY PAGE COLOR</div>", unsafe_allow_html=True)
    col_pc, col_pc_reset = st.columns([3, 1])
    with col_pc:
        pc_default = st.session_state.page_color if st.session_state.page_color else ("#141414" if dark else "#ffffff")
        new_pc = st.color_picker("Page color", value=pc_default, key="cp_page", label_visibility="collapsed")
        if new_pc != st.session_state.page_color:
            st.session_state.page_color = new_pc
            st.rerun()
    with col_pc_reset:
        if st.button("Reset", key="pc_reset", use_container_width=True):
            st.session_state.page_color = ""
            st.rerun()

    st.markdown("<hr>", unsafe_allow_html=True)

    st.markdown(f"<div style='font-size:.6rem;letter-spacing:.2em;color:{SUB};margin-bottom:14px;'>CHANGE PASSWORD</div>", unsafe_allow_html=True)
    
    if "pw_msg" not in st.session_state: st.session_state.pw_msg = ("", "")

    if st.session_state.pw_step == 1:
        st.markdown(f"<p style='font-size:12px;color:{SUB};'>To change your password, we need to verify your email.</p>", unsafe_allow_html=True)
        
        if st.button("SEND OTP TO MY EMAIL", use_container_width=True, key="req_pw_otp"):
            user_email = get_user_email(username)
            if not user_email:
                st.session_state.pw_msg = ("No email registered to this account. Cannot reset via OTP.", "err")
            else:
                generated_otp = str(random.randint(100000, 999999))
                success, err_msg = send_otp_email(user_email, generated_otp, "password")
                if success:
                    st.session_state.pw_step = 2
                    st.session_state.pw_data = {"otp": generated_otp, "email": user_email}
                    st.session_state.pw_msg = ("", "")
                else:
                    st.session_state.pw_msg = (err_msg, "err")
            st.rerun()

    elif st.session_state.pw_step == 2:
        st.markdown(f"<p style='font-size:12px;color:{SUB};'>Enter the OTP sent to {st.session_state.pw_data.get('email')}</p>", unsafe_allow_html=True)
        
        pw_otp  = st.text_input("OTP", key="s_pw_otp", placeholder="6-digit OTP")
        new_pw  = st.text_input("NEW PASSWORD", type="password", key="s_new_pw", placeholder="6+ characters")
        new_pw2 = st.text_input("CONFIRM NEW PASSWORD", type="password", key="s_new_pw2", placeholder="")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("CANCEL", use_container_width=True, key="cancel_pw_change"):
                st.session_state.pw_step = 1
                st.session_state.pw_data = {}
                st.session_state.pw_msg = ("", "")
                st.rerun()
        with col2:
            if st.button("UPDATE PASSWORD", use_container_width=True, key="s_pw_btn"):
                # Pull directly from Streamlit's deep memory
                entered_otp = str(st.session_state.s_pw_otp).strip()
                real_otp = str(st.session_state.pw_data.get("otp")).strip()
                
                if not entered_otp or not new_pw or not new_pw2: 
                    st.session_state.pw_msg = ("Please fill in all fields.", "err")
                elif entered_otp != real_otp:
                    st.session_state.pw_msg = ("Invalid OTP.", "err")
                elif new_pw != new_pw2: 
                    st.session_state.pw_msg = ("New passwords do not match.", "err")
                elif len(new_pw) < 6: 
                    st.session_state.pw_msg = ("New password must be 6+ characters.", "err")
                else:
                    ok, msg = change_password_with_otp(username, new_pw)
                    st.session_state.pw_msg = (msg, "ok" if ok else "err")
                    if ok:
                        st.session_state.pw_step = 1
                        st.session_state.pw_data = {}
                st.rerun()

    pw_text, pw_kind = st.session_state.pw_msg
    if pw_text:
        colour = FG if pw_kind == "ok" else "#cc4444"
        st.markdown(f"<p style='font-size:11px;letter-spacing:.1em;color:{colour};margin-top:6px;'>{pw_text}</p>", unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)

    st.markdown(f"<div style='font-size:.6rem;letter-spacing:.2em;color:{SUB};margin-bottom:14px;'>REVISION HISTORY</div>", unsafe_allow_html=True)
    scripts = get_scripts(username)
    names   = list(scripts.keys())

    if names:
        for sname in names:
            revs = get_revisions(username, sname)
            col_sn, col_cnt, col_clr = st.columns([4, 1, 1])
            with col_sn: st.markdown(f"<div style='font-size:.8rem;letter-spacing:.1em;color:{FG};padding:6px 0;border-bottom:1px solid {BRD};'>{sname.upper()}</div>", unsafe_allow_html=True)
            with col_cnt: st.markdown(f"<div style='font-size:.7rem;color:{SUB};padding:8px 0 0 0;text-align:center;'>{len(revs)} rev.</div>", unsafe_allow_html=True)
            with col_clr:
                if st.button("Clear", key=f"clr_{sname}", use_container_width=True):
                    clear_script_history(username, sname)
                    st.rerun()
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("Clear All History", use_container_width=True, key="clr_all_btn"):
            clear_all_history(username)
            st.rerun()
    else:
        st.markdown(f"<p style='font-size:.75rem;color:{SUB};letter-spacing:.1em;'>No scripts yet.</p>", unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)

    st.markdown(f"<div style='font-size:.6rem;letter-spacing:.2em;color:{SUB};margin-bottom:14px;'>ACCOUNT</div>", unsafe_allow_html=True)
    if st.button("LOGOUT", use_container_width=True, key="settings_logout_btn"):
        st.session_state.logged_in  = False
        st.session_state.username   = ""
        st.session_state.script     = None
        st.session_state.page       = "dashboard"
        st.session_state.focus_mode = False
        st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(page_title="Ink Play", page_icon="🎬", layout="wide", initial_sidebar_state="collapsed")
    init_session()
    global_css(st.session_state.dark_mode)

    if not st.session_state.logged_in:
        page_auth()
    elif st.session_state.page == "dashboard":
        page_dashboard()
    elif st.session_state.page == "settings":
        page_settings()
    else:
        page_app()

if __name__ == "__main__":
    main()