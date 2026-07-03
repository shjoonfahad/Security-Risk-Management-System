from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from io import BytesIO
import sqlite3
import csv
import io
import os
import random
from functools import wraps

APP_TITLE = "UOH Cybersecurity – Risk Management System"

app = Flask(__name__)
app.secret_key = 'uoh_cybersecurity_2025_secret_key'

# 15 minutes session timeout
SESSION_TIMEOUT_SECONDS = 15 * 60
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT_SECONDS)

DB_PATH = os.path.join(os.path.dirname(__file__), 'security_assets.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  full_name TEXT,
                  email TEXT,
                  department TEXT,
                  role TEXT,
                  created_date TEXT,
                  last_login TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS assets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  asset_name TEXT NOT NULL,
                  asset_type TEXT,
                  department TEXT,
                  likelihood INTEGER,
                  impact INTEGER,
                  risk_score INTEGER,
                  risk_level TEXT,
                  notes TEXT,
                  added_by TEXT,
                  date_added TEXT,
                  last_updated TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user TEXT,
                  action TEXT,
                  details TEXT,
                  timestamp TEXT)''')

    # create default admin if missing
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_pw = generate_password_hash('admin123')
        c.execute('''INSERT INTO users (username, password, full_name, email, department, role, created_date, last_login)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  ('admin', hashed_pw, 'System Administrator', 'admin@uoh.edu.sa',
                   'IT Security', 'Administrator',
                   datetime.now().strftime('%Y-%m-%d %H:%M:%S'), None))

    # seed sample data if few
    c.execute("SELECT COUNT(*) AS n FROM assets")
    n = c.fetchone()['n']
    if n < 30:
        samples = [
            ('Primary Domain Controller', 'Server', 'IT Security', 5, 5, 'Active Directory authentication'),
            ('Core Network Router', 'Network Device', 'Network Operations', 4, 5, 'Main gateway for all traffic'),
            ('Student Records Database', 'Database', 'Administration', 5, 5, 'Contains all student information'),
            ('Financial ERP System', 'Application', 'Finance', 5, 5, 'Handles financial transactions'),
            ('Email Server', 'Server', 'IT Services', 4, 5, 'University-wide email'),
            ('VPN Gateway', 'Network Device', 'IT Security', 4, 4, 'Remote access gateway'),
            ('Backup Server', 'Server', 'IT Operations', 3, 5, 'Daily backup system'),
            ('WiFi Controllers', 'Network Device', 'Network Operations', 3, 3, 'Campus wireless network'),
            ('Web Application Firewall', 'Network Device', 'IT Security', 3, 4, 'Web protection'),
            ('Library Management System', 'Application', 'Library', 2, 3, 'Book lending system'),
            ('SIEM Platform', 'Application', 'IT Security', 3, 4, 'Log correlation'),
            ('IDS/IPS', 'Network Device', 'IT Security', 4, 4, 'Intrusion prevention'),
            ('LMS', 'Application', 'Academic Affairs', 3, 4, 'Online classes'),
            ('Admission System', 'Application', 'Admissions', 3, 4, 'Applications intake'),
            ('HR Management', 'Application', 'Human Resources', 4, 4, 'Employees data'),
        ]
        for asset in samples:
            score = asset[3] * asset[4]
            level = 'High' if score >= 15 else ('Medium' if score >= 8 else 'Low')
            days_ago = random.randint(1, 60)
            date = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d %H:%M:%S')
            c.execute('''INSERT INTO assets
                         (asset_name, asset_type, department, likelihood, impact, risk_score, risk_level, notes,
                          added_by, date_added, last_updated)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (asset[0], asset[1], asset[2], asset[3], asset[4], score, level, asset[5], 'admin', date, date))

        # activity examples
        acts = [
            ('admin', 'Login', 'User logged in successfully'),
            ('admin', 'Seed DB', 'Inserted demo assets'),
            ('admin', 'Report Generated', 'Monthly risk report generated'),
        ]
        for u, a, d in acts:
            c.execute('INSERT INTO activity_logs (user, action, details, timestamp) VALUES (?, ?, ?, ?)',
                      (u, a, d, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    conn.commit()
    conn.close()

def log_activity(user, action, details):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO activity_logs (user, action, details, timestamp) VALUES (?, ?, ?, ?)',
                  (user, action, details, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
    except:
        pass

def calculate_risk(likelihood, impact):
    score = int(likelihood) * int(impact)
    if score >= 15:
        return score, 'High'
    elif score >= 8:
        return score, 'Medium'
    else:
        return score, 'Low'

# ---- session / auth helpers
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # timeout
        last = session.get('last_activity')
        now = datetime.utcnow().timestamp()
        if last and (now - last) > SESSION_TIMEOUT_SECONDS:
            user = session.get('username', 'Unknown')
            session.clear()
            flash('Session expired. Please login again.', 'warning')
            log_activity(user, 'Session Timeout', 'Auto logout due to inactivity')
            return redirect(url_for('login'))
        session['last_activity'] = now
        return fn(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

# ---------- Auth ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name'] or user['username']
            session['role'] = user['role'] or 'User'
            session['last_activity'] = datetime.utcnow().timestamp()
            log_activity(user['username'], 'Login', 'User logged in')
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html', app_title=APP_TITLE)

@app.route('/logout')
def logout():
    user = session.get('username', 'Unknown')
    session.clear()
    flash('Logged out successfully.', 'info')
    log_activity(user, 'Logout', 'User logged out')
    return redirect(url_for('login'))

# ---------- Dashboard ----------
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM assets ORDER BY risk_score DESC, date_added DESC')
    assets = c.fetchall()

    # stats
    total = len(assets)
    high = len([a for a in assets if a['risk_level'] == 'High'])
    med = len([a for a in assets if a['risk_level'] == 'Medium'])
    low = len([a for a in assets if a['risk_level'] == 'Low'])

    # recent logs
    c.execute('SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 10')
    logs = c.fetchall()

    # Risk Insights
    # 1) Most critical (highest risk score then newest)
    top_asset = assets[0] if assets else None

    # 2) 30-day delta: compare last 30 days vs previous 30 days
    now = datetime.now()
    last_30 = (now - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
    prev_60 = (now - timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S')

    c.execute('SELECT AVG(risk_score) AS avg1 FROM assets WHERE date_added >= ?', (last_30,))
    avg_last = c.fetchone()['avg1'] or 0

    c.execute('SELECT AVG(risk_score) AS avg2 FROM assets WHERE date_added >= ? AND date_added < ?', (prev_60, last_30))
    avg_prev = c.fetchone()['avg2'] or 0

    delta_pct = 0
    if avg_prev and avg_last:
        try:
            delta_pct = round(((avg_last - avg_prev) / avg_prev) * 100, 1)
        except ZeroDivisionError:
            delta_pct = 0

    conn.close()

    return render_template(
        'dashboard.html',
        stats={'total': total, 'high': high, 'medium': med, 'low': low},
        logs=logs,
        top_asset=top_asset,
        delta_pct=delta_pct,
        app_title=APP_TITLE,
        title="Dashboard"
    )

# ---------- Assets ----------
@app.route('/assets')
@login_required
def assets_page():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM assets ORDER BY date_added DESC')
    all_assets = c.fetchall()
    departments = sorted({ (a['department'] or '') for a in all_assets if a['department'] })
    conn.close()
    return render_template('assets.html', all_assets=all_assets, departments=departments, app_title=APP_TITLE, title="Assets")

# ---------- Activity ----------
@app.route('/activity')
@login_required
def activity():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 200')
    logs = c.fetchall()
    conn.close()
    return render_template('activity.html', logs=logs, app_title=APP_TITLE, title="Activity")

# ---------- Settings / About ----------
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', app_title=APP_TITLE, title="Settings")

@app.route('/about')
@login_required
def about():
    return render_template('about.html', app_title=APP_TITLE, title="About")

# ---------- Alerts (UI) ----------
@app.route('/alerts')
@login_required
def alerts_page():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM assets WHERE risk_level = "High" ORDER BY date_added DESC')
    alerts = c.fetchall()
    conn.close()
    return render_template('alerts.html', alerts=alerts, app_title=APP_TITLE, title="Alerts")

# ---------- Export (CSV) ----------
@app.route('/export/csv')
@login_required
def export_csv():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM assets ORDER BY id ASC')
    assets = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Asset Name', 'Type', 'Department', 'Likelihood', 'Impact', 'Risk Score', 'Risk Level', 'Notes', 'Added By', 'Date Added', 'Last Updated'])
    for a in assets:
        writer.writerow([
            a['id'], a['asset_name'], a['asset_type'], a['department'],
            a['likelihood'], a['impact'], a['risk_score'], a['risk_level'],
            a['notes'], a['added_by'], a['date_added'], a['last_updated']
        ])
    output.seek(0)

    log_activity(session['username'], 'Export', 'Exported assets to CSV')
    return send_file(BytesIO(output.getvalue().encode()),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name=f'uoh_assets_{datetime.now().strftime("%Y%m%d")}.csv')

# ---------- Print (browser print to PDF) ----------
@app.route('/dashboard/print')
@login_required
def dashboard_print():
    # صفحة مطبوعة خفيفة للطباعة / تحويل PDF من المتصفح
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM assets ORDER BY risk_score DESC, date_added DESC')
    assets = c.fetchall()
    c.execute('SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 20')
    logs = c.fetchall()
    conn.close()

    total = len(assets)
    high = len([a for a in assets if a['risk_level'] == 'High'])
    med = len([a for a in assets if a['risk_level'] == 'Medium'])
    low = len([a for a in assets if a['risk_level'] == 'Low'])

    return render_template('print_dashboard.html',
                           stats={'total': total, 'high': high, 'medium': med, 'low': low},
                           assets=assets, logs=logs, app_title=APP_TITLE, title="Dashboard Report")

# ---------- API ----------
@app.route('/api/add_asset', methods=['POST'])
@login_required
def add_asset():
    data = request.json
    likelihood = int(data['likelihood'])
    impact = int(data['impact'])
    score, level = calculate_risk(likelihood, impact)

    conn = get_db()
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''INSERT INTO assets (asset_name, asset_type, department, likelihood, impact, risk_score, risk_level, notes, added_by, date_added, last_updated)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (data['asset_name'], data['asset_type'], data.get('department', ''),
               likelihood, impact, score, level, data.get('notes', ''),
               session['username'], now, now))
    conn.commit()
    conn.close()

    log_activity(session['username'], 'Asset Added', f"Added: {data['asset_name']}")
    return jsonify({'success': True})

@app.route('/api/edit_asset', methods=['POST'])
@login_required
def edit_asset():
    data = request.json
    likelihood = int(data['likelihood'])
    impact = int(data['impact'])
    score, level = calculate_risk(likelihood, impact)

    conn = get_db()
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''UPDATE assets SET asset_name=?, asset_type=?, department=?, likelihood=?, impact=?, risk_score=?, risk_level=?, notes=?, last_updated=? WHERE id=?''',
              (data['asset_name'], data['asset_type'], data.get('department', ''),
               likelihood, impact, score, level, data.get('notes', ''), now, data['id']))
    conn.commit()
    conn.close()

    log_activity(session['username'], 'Asset Updated', f"Updated ID: {data['id']}")
    return jsonify({'success': True})

@app.route('/api/delete_asset', methods=['POST'])
@login_required
def delete_asset():
    data = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM assets WHERE id=?', (data['id'],))
    conn.commit()
    conn.close()

    log_activity(session['username'], 'Asset Deleted', f"Deleted ID: {data['id']}")
    return jsonify({'success': True})

@app.route('/api/upload_csv', methods=['POST'])
@login_required
def upload_csv():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)

        conn = get_db()
        c = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        count = 0

        for row in csv_reader:
            likelihood = int(row.get('likelihood', 1))
            impact = int(row.get('impact', 1))
            score, level = calculate_risk(likelihood, impact)
            c.execute('''INSERT INTO assets (asset_name, asset_type, department, likelihood, impact, risk_score, risk_level, notes, added_by, date_added, last_updated)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (row.get('asset_name', 'Unknown'), row.get('asset_type', 'Other'),
                       row.get('department', ''), likelihood, impact, score, level,
                       row.get('notes', ''), session['username'], now, now))
            count += 1

        conn.commit()
        conn.close()

        log_activity(session['username'], 'CSV Upload', f'Imported {count} assets')
        return jsonify({'success': True, 'message': f'Successfully uploaded {count} assets'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Notifications API (bell) ---
@app.route('/api/alerts')
@login_required
def api_alerts():
    # return latest high-risk in last 7 days + counts
    conn = get_db()
    c = conn.cursor()
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('SELECT * FROM assets WHERE risk_level="High" AND date_added>=? ORDER BY date_added DESC LIMIT 10', (week_ago,))
    rows = [dict(r) for r in c.fetchall()]

    c.execute('SELECT COUNT(*) AS n FROM assets WHERE risk_level="High"')
    total_high = c.fetchone()['n']
    conn.close()

    return jsonify({'count': len(rows), 'total_high': total_high, 'items': rows})

if __name__ == '__main__':
    init_db()
    print("=" * 70)
    print("✅ University of Hail - Risk Management System (Dark Professional Theme)")
    print("➡  Default admin login: admin")
    print(f"➡  DB path: {DB_PATH}")
    print("=" * 70)
    app.run(debug=True)
