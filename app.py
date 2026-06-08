import joblib
import numpy as np
import os
import pandas as pd
from werkzeug.utils import secure_filename
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import EMAIL, APP_PASSWORD
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    send_file
)

from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.secret_key = "aishieldsecretkey"

# -------------------------------
# MySQL Configuration
# -------------------------------

app.config['MYSQL_HOST'] = os.environ.get('MYSQLHOST')
app.config['MYSQL_USER'] = os.environ.get('MYSQLUSER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQLPASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQLDATABASE')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQLPORT', 3306))

mysql = MySQL(app)

# -------------------------------
# Bcrypt
# -------------------------------

bcrypt = Bcrypt(app)

# Load AI Model
model = joblib.load("xgboost_model.pkl")
encoder = joblib.load("protocol_encoder.pkl")

def send_attack_email(
    ip,
    requests,
    protocol,
    risk
):

    subject = "🚨 AI Shield Cloud Alert"

    body = f"""
DDoS Attack Detected

IP Address : {ip}

Requests : {requests}

Protocol : {protocol}

Risk Level : {risk}

Please Investigate Immediately.
"""

    message = MIMEMultipart()

    message["From"] = EMAIL
    message["To"] = EMAIL
    message["Subject"] = subject

    message.attach(
        MIMEText(body, "plain")
    )

try:
    server = smtplib.SMTP(
        "smtp.gmail.com",
        587,
        timeout=10
    )

    server.ehlo()
    server.starttls()
    server.ehlo()

    server.login(
        EMAIL,
        APP_PASSWORD
    )

    server.sendmail(
        EMAIL,
        EMAIL,
        message.as_string()
    )

    server.quit()

    print("Email Alert Sent Successfully")

except Exception as e:
    print("Email Error:", str(e))

# -------------------------------
# Home Page
# -------------------------------

@app.route('/')
def home():
    return render_template('index.html')


# -------------------------------
# About Page
# -------------------------------

@app.route('/about')
def about():
    return render_template('about.html')


# -------------------------------
# Register
# -------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode('utf-8')

        cur = mysql.connection.cursor()

        cur.execute(
            """
            INSERT INTO users(fullname,email,password)
            VALUES(%s,%s,%s)
            """,
            (fullname, email, hashed_password)
        )

        mysql.connection.commit()
        cur.close()

        return redirect(url_for('login'))

    return render_template('register.html')


# -------------------------------
# Login
# -------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        user = cur.fetchone()

        cur.close()

        if user:

            if bcrypt.check_password_hash(
                user[3],
                password
            ):

                session['user_id'] = user[0]
                session['user_name'] = user[1]

                return redirect(url_for('dashboard'))

        return "Invalid Email or Password"

    return render_template('login.html')


# -------------------------------
# Dashboard
# -------------------------------

@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) FROM uploaded_files")
    total_analyses = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM attack_logs")
    total_attacks = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_ips = cur.fetchone()[0]

    cur.close()

    return render_template(
        'dashboard.html',
        user=session['user_name'],
        total_analyses=total_analyses,
        total_attacks=total_attacks,
        blocked_ips=blocked_ips
    )

# -------------------------------
# Logout
# -------------------------------

@app.route('/logout')
def logout():

    session.clear()

    return redirect(url_for('home'))


# -------------------------------
# Upload CSV + AnalyzeC
# -------------------------------

@app.route('/upload', methods=['POST'])
def upload():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files['file']

    if not file:
        return "No File Selected"
   
    
    filename = secure_filename(file.filename)

    filepath = os.path.join(
        'uploads',
        filename
    )

    file.save(filepath)

    # Save uploaded file info

    cur = mysql.connection.cursor()

    cur.execute(
        """
        INSERT INTO uploaded_files(user_id, filename)
        VALUES(%s,%s)
        """,
        (
            session['user_id'],
            filename
        )
    )

    mysql.connection.commit()
    cur.close()



    # Read CSV

    df = pd.read_csv(filepath)

    total_records = len(df)

    max_requests = int(
        df['Requests'].max()
    )

    avg_requests = round(
        df['Requests'].mean(),
        2
    )

    suspicious_ip = df.loc[
        df['Requests'].idxmax(),
        'IP'
    ]

    # =========================
# AI Prediction
# =========================

    # =========================
    # AI Prediction
    # =========================

    protocol = df.loc[
        df['Requests'].idxmax(),
        'Protocol'
    ]

    protocol_encoded = encoder.transform(
        [protocol]
    )[0]

    prediction = model.predict(
        [[
            max_requests,
            protocol_encoded
        ]]
    )[0]

    prediction_proba = model.predict_proba(
        [[
            max_requests,
            protocol_encoded
        ]]
    )[0]

    confidence = round(
        max(prediction_proba) * 100,
        2
    )

    if prediction == 1:

        recommendation = """
        • Block IP Immediately
        • Enable Rate Limiting
        • Monitor UDP Traffic
        """

    else:

        recommendation = """
        • Continue Monitoring
        • No Immediate Threat
        """

    

    if prediction == 1:

        risk_level = "HIGH"
        attack_status = "DDoS Attack Detected"

    else:

        risk_level = "NORMAL"
        attack_status = "No Attack"
    # Save attack log

    if attack_status != "No Attack":

        protocol = df.loc[
            df['Requests'].idxmax(),
            'Protocol'
        ]

        cur = mysql.connection.cursor()

        cur.execute(
            """
            INSERT INTO attack_logs
            (
                ip_address,
                requests,
                protocol,
                risk_level,
                attack_status
            )
            VALUES(%s,%s,%s,%s,%s)
            """,
            (
                suspicious_ip,
                max_requests,
                protocol,
                risk_level,
                attack_status
            )
        )

        mysql.connection.commit()
        cur.close()

        try:
            send_attack_email(
                suspicious_ip,
                attack_type,
                confidence,
                risk_level
             )
        except Exception as e:
            print("Email Error:", e)

    return render_template(
        'analysis.html',
        filename=filename,
        total_records=total_records,
        max_requests=max_requests,
        avg_requests=avg_requests,
        suspicious_ip=suspicious_ip,
        risk_level=risk_level,
        attack_status=attack_status,
        confidence=confidence,
        recommendation=recommendation,
        records=df.to_dict(orient='records')
    )

@app.route('/attack_history')
def attack_history():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
        id,
        ip_address,
        requests,
        protocol,
        risk_level,
        attack_status,
        created_at
        FROM attack_logs
        ORDER BY id DESC
    """)

    attacks = cur.fetchall()

    cur.close()

    return render_template(
        'attack_history.html',
        attacks=attacks
    )

@app.route('/block_ip/<ip>')
def block_ip(ip):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    cur.execute(
        """
        INSERT INTO blocked_ips(ip_address, reason)
        VALUES(%s,%s)
        """,
        (
            ip,
            "DDoS Attack Detected"
        )
    )

    mysql.connection.commit()
    cur.close()

    return redirect(url_for('attack_history'))

@app.route('/analytics')
def analytics():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    # =========================
    # Dashboard Statistics
    # =========================

    cur.execute("SELECT COUNT(*) FROM uploaded_files")
    total_analyses = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM attack_logs")
    total_attacks = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_ips = cur.fetchone()[0]

    # =========================
    # Top Attacker
    # =========================

    cur.execute("""
        SELECT ip_address, COUNT(*)
        FROM attack_logs
        GROUP BY ip_address
        ORDER BY COUNT(*) DESC
        LIMIT 1
    """)

    top_ip = cur.fetchone()

    # =========================
    # Latest Attack
    # =========================

    cur.execute("""
        SELECT
            ip_address,
            protocol,
            risk_level
        FROM attack_logs
        ORDER BY id DESC
        LIMIT 1
    """)

    latest_attack = cur.fetchone()

    # =========================
    # Recent Threat Feed
    # =========================

    cur.execute("""
        SELECT
            ip_address,
            protocol,
            risk_level,
            created_at
        FROM attack_logs
        ORDER BY id DESC
        LIMIT 5
    """)

    recent_attacks = cur.fetchall()

    # =========================
    # Top Attacker Chart
    # =========================

    cur.execute("""
        SELECT
            ip_address,
            COUNT(*)
        FROM attack_logs
        GROUP BY ip_address
        ORDER BY COUNT(*) DESC
        LIMIT 5
    """)

    attackers = cur.fetchall()

    ip_labels = []
    ip_counts = []

    for row in attackers:
        ip_labels.append(row[0])
        ip_counts.append(row[1])

    # =========================
    # Accuracy
    # =========================

    accuracy = 98.5

    cur.close()

    return render_template(
        'analytics.html',
        total_analyses=total_analyses,
        total_attacks=total_attacks,
        blocked_ips=blocked_ips,
        top_ip=top_ip,
        latest_attack=latest_attack,
        recent_attacks=recent_attacks,
        ip_labels=ip_labels,
        ip_counts=ip_counts,
        accuracy=accuracy
    )

@app.route('/download_report')
def download_report():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    pdf_file = "security_report.pdf"

    doc = SimpleDocTemplate(pdf_file)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "AI Shield Cloud Security Report",
            styles['Title']
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Generated By: AI Shield Cloud",
            styles['Normal']
        )
    )

    content.append(
        Paragraph(
            "Attack Detection System",
            styles['Normal']
        )
    )

    content.append(Spacer(1, 20))

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            ip_address,
            requests,
            protocol,
            risk_level,
            attack_status,
            created_at
        FROM attack_logs
        ORDER BY id DESC
        LIMIT 1
    """)

    attack = cur.fetchone()

    cur.close()

    if attack:

        content.append(
            Paragraph(
                f"IP Address: {attack[0]}",
                styles['Heading2']
            )
        )

        content.append(
            Paragraph(
                f"Requests: {attack[1]}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"Protocol: {attack[2]}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"Risk Level: {attack[3]}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"Status: {attack[4]}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"Time: {attack[5]}",
                styles['Normal']
            )
        )

    doc.build(content)

    return send_file(
        pdf_file,
        as_attachment=True
    )

@app.route('/api/threat_feed')
def threat_feed():

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            ip_address,
            protocol,
            risk_level,
            created_at
        FROM attack_logs
        ORDER BY id DESC
        LIMIT 10
    """)

    attacks = cur.fetchall()

    cur.close()

    data = []

    for row in attacks:

        data.append({
            "ip": row[0],
            "protocol": row[1],
            "risk": row[2],
            "time": str(row[3])
        })

    return {"attacks": data}
# -------------------------------
# Run Application
# -------------------------------

if __name__ == '__main__':
    app.run(debug=True)