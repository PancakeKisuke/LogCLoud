# imports
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re

# My webapp
app = Flask(__name__)

# Secret key for sessions (IMPORTANT)
app.secret_key = 'secret-key-for-session'  # 

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logcloud.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Compile SCSS
Scss(app, static_dir='static', asset_dir='static')
  
# ==================== DATABASE TABLES ====================

class Admin(db.Model):
    __tablename__ = 'admin'
    
    userID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    lastLogin = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<Admin {self.username}>'


class Device(db.Model):
    __tablename__ = 'devices'
    
    deviceID = db.Column(db.Integer, primary_key=True)
    deviceName = db.Column(db.String(100), nullable=False)
    deviceType = db.Column(db.String(50), nullable=False)
    ipAddress = db.Column(db.String(45), nullable=False)
    status = db.Column(db.String(20), default='active')
    registeredOn = db.Column(db.DateTime, default=datetime.utcnow)
    logs = db.relationship('LogEntry', backref='device', lazy=True)
    
    def __repr__(self):
        return f'<Device {self.deviceName}>'


class LogEntry(db.Model):
    __tablename__ = 'Log_entry'
    
    LogID = db.Column(db.Integer, primary_key=True)
    sourceDevice = db.Column(db.Integer, db.ForeignKey('devices.deviceID'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ipAddress = db.Column(db.String(45), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    message = db.Column(db.Text, nullable=False)
    rawlog = db.Column(db.Text, nullable=True)
    isFlagged = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='received')
    alerts = db.relationship('Alert', backref='log', lazy=True)
    
    def __repr__(self):
        return f'<LogEntry {self.LogID} from Device {self.sourceDevice}>'


class Alert(db.Model):
    __tablename__ = 'alerts'
    
    alertID = db.Column(db.Integer, primary_key=True)
    logID = db.Column(db.Integer, db.ForeignKey('Log_entry.LogID'), nullable=False)
    alertType = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    
    def __repr__(self):
        return f'<Alert {self.alertID} - {self.alertType} ({self.severity})>'


# ==================== LOGIC CLASSES ====================

class LogCollector:
    """Class to handle log collection from devices"""

    @staticmethod
    def collect_log(raw_log, device_id):
        """Receive a raw log and process it"""
        try:
            device = Device.query.get(device_id)
            if not device:
                raise ValueError(f"Device with ID {device_id} not found")

            parsed_data = LogParser.parse_log(raw_log)

            log_entry = LogEntry(
                sourceDevice=device_id,
                ipAddress=parsed_data.get('ipAddress'),
                severity=parsed_data.get('severity', 'info'),
                message=parsed_data.get('message', raw_log),
                rawlog=raw_log,
                status='parsed'
            )

            db.session.add(log_entry)
            db.session.commit()

            LogProcessor.analyze(log_entry)

            return log_entry

        except Exception as e:
            print(f"Error collecting log: {e}")
            db.session.rollback()
            return None


class LogParser:
    """Parses raw log data into structured format"""

    @staticmethod
    def parse_log(raw_log: str) -> dict:
        parsing_data = {
            'ipAddress': None,
            'severity': 'info',
            'message': raw_log,
        }

        # Extract IPv4 address
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ip_match = re.search(ip_pattern, raw_log)
        if ip_match:
            parsing_data['ipAddress'] = ip_match.group()

        # Determine severity
        raw_lower = raw_log.lower()
        if 'critical' in raw_lower or 'fatal' in raw_lower:
            parsing_data['severity'] = 'critical'
        elif 'error' in raw_lower or 'fail' in raw_lower:
            parsing_data['severity'] = 'error'
        elif 'warn' in raw_lower:
            parsing_data['severity'] = 'warning'
        else:
            parsing_data['severity'] = 'info'

        # Remove timestamp
        timestamp_pattern = r'^[\d\-:\s]+\s+'
        message = re.sub(timestamp_pattern, '', raw_log)
        parsing_data['message'] = message.strip()

        return parsing_data


class LogProcessor:
    """Analyzes logs for suspicious patterns"""
    
    THREAT_PATTERNS = {
        'Failed_login': [
            r'failed login',
            r'authentication failed',
            r'invalid password',
            r'login attempt failed',
            r'access denied'
        ],
        'Unauthorized_access': [
            r'unauthorized access',
            r'permission denied',
            r'access violation',
            r'forbidden'
        ],
        'Brute_force': [
            r'multiple failed attempts',
            r'repeated login failures',
            r'brute force'
        ],
        'Suspicious_activity': [
            r'suspicious',
            r'anomaly detected',
            r'unusual activity'
        ]
    }
    
    @staticmethod
    def analyze(log_entry):
        """Analyze a log entry for threats"""
        message_lower = log_entry.message.lower()
        
        for threat_type, patterns in LogProcessor.THREAT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    log_entry.isFlagged = True
                    log_entry.status = 'flagged'
                    
                    severity = LogProcessor._determine_severity(threat_type, log_entry.severity)
                    
                    alert = Alert(
                        logID=log_entry.LogID,
                        alertType=threat_type,
                        severity=severity,
                        description=f"{threat_type} detected: {log_entry.message[:100]}",
                        status='pending'
                    )
                    
                    db.session.add(alert)
                    return
        
        log_entry.status = 'analyzed'
    
    @staticmethod
    def _determine_severity(threat_type, log_severity):
        """Determine alert severity"""
        severity_map = {
            'Failed_login': 'MEDIUM',
            'Unauthorized_access': 'HIGH',
            'Brute_force': 'CRITICAL',
            'Suspicious_activity': 'MEDIUM'
        }
        
        base_severity = severity_map.get(threat_type, 'LOW')
        
        if log_severity and log_severity.upper() == 'CRITICAL':
            return 'CRITICAL'
        elif log_severity and log_severity.upper() == 'ERROR' and base_severity in ['LOW', 'MEDIUM']:
            return 'HIGH'
        
        return base_severity


# ==================== ROUTES ====================

@app.route("/")
def index():
    """Redirect to login page"""
    return redirect(url_for('login'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.userID
            session['username'] = admin.username
            
            admin.lastLogin = datetime.now()
            db.session.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('login.html')
    
    return render_template('login.html')


@app.route("/dashboard")
def dashboard():
    """Main dashboard"""
    if 'admin_id' not in session:
        flash('Please login to access the dashboard', 'error')
        return redirect(url_for('login'))
    
    # Get real statistics
    total_logs = LogEntry.query.count()
    active_alerts = Alert.query.filter_by(status='pending').count()
    total_devices = Device.query.count()
    flagged_logs = LogEntry.query.filter_by(isFlagged=True).count()
    
    username = session.get('username', 'Admin')
    
    return render_template('dashboard.html', 
                          username=username,
                          total_logs=total_logs,
                          active_alerts=active_alerts,
                          total_devices=total_devices,
                          flagged_logs=flagged_logs)


@app.route("/submit-log", methods=['GET', 'POST'])
def submit_log():
    """Submit logs for processing"""
    if 'admin_id' not in session:
        flash('Please login', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        device_id = request.form.get('device_id')
        
        if not device_id:
            flash('Please select a device', 'error')
            return render_template('submit_log.html', devices=Device.query.all())
        
        # File upload
        if 'log_file' in request.files and request.files['log_file'].filename != '':
            file = request.files['log_file']
            try:
                content = file.read().decode('utf-8')
                lines = content.strip().split('\n')
                
                processed = 0
                flagged = 0
                
                for line in lines:
                    if line.strip():
                        log_entry = LogCollector.collect_log(line.strip(), int(device_id))
                        if log_entry:
                            processed += 1
                            if log_entry.isFlagged:
                                flagged += 1
                
                flash(f'✅ Processed {processed} logs. {flagged} threat(s) detected!', 'success')
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
        
        # Single log
        elif request.form.get('raw_log'):
            raw_log = request.form.get('raw_log')
            try:
                log_entry = LogCollector.collect_log(raw_log, int(device_id))
                
                if log_entry:
                    if log_entry.isFlagged:
                        flash(f'⚠️ Threat detected! Alert created. Log ID: {log_entry.LogID}', 'warning')
                    else:
                        flash(f'✅ Log processed successfully. Log ID: {log_entry.LogID}', 'success')
                else:
                    flash('❌ Error processing log', 'error')
            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
        else:
            flash('Please provide a log message or upload a file', 'error')
    
    devices = Device.query.all()
    return render_template('submit_log.html', devices=devices)


@app.route("/logs")
def view_logs():
    """View all logs"""
    if 'admin_id' not in session:
        flash('Please login', 'error')
        return redirect(url_for('login'))
    
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).all()
    devices = Device.query.all()
    
    return render_template('view_logs.html', logs=logs, devices=devices)


@app.route("/logs/search", methods=['GET'])
def search_logs():
    """Search and filter logs"""
    if 'admin_id' not in session:
        flash('Please login', 'error')
        return redirect(url_for('login'))
    
    device_id = request.args.get('device_id', type=int)
    severity = request.args.get('severity')
    flagged_only = request.args.get('flagged_only', 'false') == 'true'
    search_query = request.args.get('search', '').strip()
    
    query = LogEntry.query
    
    if device_id:
        query = query.filter_by(sourceDevice=device_id)
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if flagged_only:
        query = query.filter_by(isFlagged=True)
    
    if search_query:
        query = query.filter(LogEntry.message.contains(search_query))
    
    logs = query.order_by(LogEntry.timestamp.desc()).all()
    devices = Device.query.all()
    
    return render_template('view_logs.html', logs=logs, devices=devices, 
                          selected_device=device_id, selected_severity=severity,
                          flagged_only=flagged_only, search_query=search_query)


@app.route("/alerts")
def view_alerts():
    """View all alerts"""
    if 'admin_id' not in session:
        flash('Please login', 'error')
        return redirect(url_for('login'))
    
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    
    return render_template('view_alerts.html', alerts=alerts)


@app.route("/alerts/filter", methods=['GET'])
def filter_alerts():
    """Filter alerts"""
    if 'admin_id' not in session:
        flash('Please login', 'error')
        return redirect(url_for('login'))
    
    status = request.args.get('status')
    severity = request.args.get('severity')
    alert_type = request.args.get('alert_type')
    
    query = Alert.query
    
    if status:
        query = query.filter_by(status=status)
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if alert_type:
        query = query.filter_by(alertType=alert_type)
    
    alerts = query.order_by(Alert.timestamp.desc()).all()
    
    return render_template('view_alerts.html', alerts=alerts,
                          selected_status=status, selected_severity=severity,
                          selected_alert_type=alert_type)


@app.route("/alert/<int:alert_id>/acknowledge", methods=['POST'])
def acknowledge_alert(alert_id):
    """Mark alert as acknowledged"""
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    
    alert = Alert.query.get(alert_id)
    if alert:
        alert.status = 'acknowledged'
        db.session.commit()
        flash('Alert acknowledged', 'success')
    
    return redirect(url_for('view_alerts'))


@app.route("/alert/<int:alert_id>/resolve", methods=['POST'])
def resolve_alert(alert_id):
    """Mark alert as resolved"""
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    
    alert = Alert.query.get(alert_id)
    if alert:
        alert.status = 'resolved'
        db.session.commit()
        flash('Alert resolved', 'success')
    
    return redirect(url_for('view_alerts'))


@app.route("/logout")
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))


# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database"""
    with app.app_context():
        db.create_all()
        
        if Admin.query.filter_by(username='admin').first() is None:
            default_admin = Admin(
                username='admin',
                password=generate_password_hash('admin123')
            )
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin user created: username='admin', password='admin123'")
        else:
            print("Admin user already exists")
        
        if Device.query.count() == 0:
            test_devices = [
                Device(deviceName='Router-01', deviceType='router', ipAddress='192.168.1.1'),
                Device(deviceName='Firewall-01', deviceType='firewall', ipAddress='192.168.1.10'),
                Device(deviceName='Server-01', deviceType='server', ipAddress='192.168.1.100')
            ]
            for device in test_devices:
                db.session.add(device)
            db.session.commit()
            print("Test devices added")
        else:
            print("Devices already exist")


# ==================== RUN APPLICATION ====================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)