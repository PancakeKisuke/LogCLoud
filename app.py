# imports
from flask import Flask, render_template, request, redirect, url_for, session, flash
#from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re

# My webapp
app = Flask(__name__)

# Secret key for sessions (IMPORTANT)
app.secret_key = 'secret-key-for-session'  # Change this to a random secret key in production

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logcloud.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Compile SCSS
#Scss(app, static_dir='static', asset_dir='static')
  
# ==================== DATABASE TABLES ====================
# this section defines the database tables for all my classes

class Admin(db.Model):
    __tablename__ = 'admin'
    
    userID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    lastLogin = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, username=None, password=None):
        if username:
            self.username = username
        if password:
            self.password = password
    
    def __repr__(self):
        return f'<Admin {self.username}>'

class Device(db.Model):
    __tablename__ = 'devices'
    
    deviceID = db.Column(db.Integer, primary_key=True)
    deviceName = db.Column(db.String(100), nullable=False)
    deviceType = db.Column(db.String(50), nullable=False)
    ipAddress = db.Column(db.String(45), nullable=False)  # IPv6 compatible just incase waabona
    status = db.Column(db.String(20), default='active')
    registeredOn = db.Column(db.DateTime, default=datetime.utcnow)
    logs = db.relationship('LogEntry', backref='device', lazy=True)
    
    def __init__(self, deviceName=None, deviceType=None, ipAddress=None, status='active'):
        if deviceName:
            self.deviceName = deviceName
        if deviceType:
            self.deviceType = deviceType
        if ipAddress:
            self.ipAddress = ipAddress
        self.status = status
    
    def __repr__(self):
        return f'<Device {self.deviceName}>' # these are useful for debugging

class LogEntry(db.Model):
    __tablename__ = 'Log_entry'
    
    LogID = db.Column(db.Integer, primary_key=True)
    # foreign key should reference the devices table declared in Device.__tablename__
    sourceDevice = db.Column(db.Integer, db.ForeignKey('devices.deviceID'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # time log was received
    ipAddress = db.Column(db.String(45), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    message = db.Column(db.Text, nullable=False)
    rawlog = db.Column(db.Text, nullable=True)
    isFlagged = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='received')
    alerts = db.relationship('Alert', backref='log', lazy=True)
    
    def __init__(self, sourceDevice=None, ipAddress=None, severity=None, message=None, rawlog=None, status='received'):
        if sourceDevice:
            self.sourceDevice = sourceDevice
        self.ipAddress = ipAddress
        self.severity = severity
        if message:
            self.message = message
        self.rawlog = rawlog
        self.status = status
        self.isFlagged = False
    
    def __repr__(self):
        return f'<LogEntry {self.LogID} from Device {self.sourceDevice}>'


class Alert(db.Model):
    __tablename__ = 'alerts'
    
    alertID = db.Column(db.Integer, primary_key=True)
    logID = db.Column(db.Integer, db.ForeignKey('Log_entry.LogID'), nullable=False)
    alertType = db.Column(db.String(50), nullable=False) # e.g., "High Severity Log", "Multiple Failed Logins"
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # status should be a string with values like 'pending', 'acknowledged', 'resolved'
    status = db.Column(db.String(20), default='pending') # pending, acknowledged, resolved
    
    def __init__(self, logID=None, alertType=None, severity=None, description=None, status='pending'):
        if logID:
            self.logID = logID
        if alertType:
            self.alertType = alertType
        if severity:
            self.severity = severity
        self.description = description
        self.status = status
    
    def __repr__(self):
        return f'<Alert {self.alertID} - {self.alertType} ({self.severity})>' # useful for debugging


# ==================== LOGIC CLASSES ====================

class LogCollector:
    """Class to handle log collection from devices"""

    def __init__(self):
        pass

    @staticmethod
    def collect_log(raw_log, device_id):
        """Receive a raw log and process it

        Args:
            raw_log (str): The raw log data
            device_id (int): The ID of the source device

        Returns:
            LogEntry | None: The created log entry or None on error
        """
        try:
            device = Device.query.get(device_id)
            if not device:
                raise ValueError(f"Device with ID {device_id} not found")

            parsed_log = LogParser.parse_log(raw_log)

            # Create the LogEntry and persist it so it has a primary key
            log_entry = LogEntry(
                sourceDevice=device_id,
                ipAddress=parsed_log.get('ipAddress'),
                severity=parsed_log.get('severity', 'info'),
                message=parsed_log.get('message'),
                rawlog=raw_log,
                status='parsed'
            )

            db.session.add(log_entry)
            db.session.commit()  # now log_entry.LogID is available

            # Process the log (may create alerts, update flags, etc.)
            LogProcessor.process_log(log_entry)

            return log_entry

        except Exception as e:
            print(f"Error collecting log: {e}")
            db.session.rollback()
            return None


class LogParser:
    """Enhanced parser that supports multiple common log formats."""

    @staticmethod
    def parse_log(raw_log: str) -> dict:
        """
        Auto-detect and parse common log formats.
        Supports: Syslog, Apache/Nginx, Windows Event, Firewall, Generic logs
        
        Args:
            raw_log (str): Raw log string
            
        Returns:
            dict: Parsed log data with ipAddress, severity, message
        """
        # Try different parsers in order
        parsers = [
            LogParser._parse_syslog,
            LogParser._parse_apache_nginx,
            LogParser._parse_windows_event,
            LogParser._parse_firewall,
            LogParser._parse_generic
        ]
        
        for parser in parsers:
            result = parser(raw_log)
            if result:
                return result
        
        # Fallback to generic if nothing matches
        return LogParser._parse_generic(raw_log)
    
    @staticmethod
    def _parse_syslog(raw_log: str):
        """
        Parse RFC 3164/5424 Syslog format
        Examples:
        - <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
        - Oct 26 15:30:01 router1 sshd[1234]: Failed password for admin from 192.168.1.100
        """
        # Pattern for syslog with priority
        syslog_priority = r'^<(\d+)>'
        # Pattern for standard syslog
        syslog_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(\[\d+\])?\s*:\s*(.+)$'
        
        # Remove priority if present
        log_content = re.sub(syslog_priority, '', raw_log)
        
        match = re.match(syslog_pattern, log_content.strip())
        if match:
            timestamp, hostname, process, pid, message = match.groups()
            
            return {
                'ipAddress': LogParser._extract_ip(message),
                'severity': LogParser._determine_severity(message),
                'message': message.strip(),
                'format': 'syslog',
                'hostname': hostname,
                'process': process
            }
        return None
    
    @staticmethod
    def _parse_apache_nginx(raw_log: str):
        """
        Parse Apache/Nginx access logs
        Example: 192.168.1.100 - - [26/Oct/2024:15:30:01 +0000] "GET /admin HTTP/1.1" 404 512
        """
        # Combined Log Format pattern
        apache_pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)'
        
        match = re.match(apache_pattern, raw_log)
        if match:
            ip, timestamp, method, url, status_code, size = match.groups()
            
            # Determine severity based on status code
            status = int(status_code)
            if status >= 500:
                severity = 'error'
            elif status >= 400:
                severity = 'warning'
            else:
                severity = 'info'
            
            message = f"{method} {url} - Status {status_code}"
            
            return {
                'ipAddress': ip,
                'severity': severity,
                'message': message,
                'format': 'apache/nginx',
                'status_code': status_code,
                'url': url
            }
        return None
    
    @staticmethod
    def _parse_windows_event(raw_log: str):
        """
        Parse Windows Event Log format
        Example: Event ID: 4625, Level: Error, Source: Security, Message: An account failed to log on
        """
        # Look for Windows Event patterns
        event_pattern = r'Event ID:\s*(\d+).*?Level:\s*(\w+).*?Message:\s*(.+?)(?:\s*$|\s*,)'
        
        match = re.search(event_pattern, raw_log, re.IGNORECASE | re.DOTALL)
        if match:
            event_id, level, message = match.groups()
            
            # Map Windows levels to our severity
            severity_map = {
                'critical': 'critical',
                'error': 'error',
                'warning': 'warning',
                'information': 'info',
                'info': 'info'
            }
            severity = severity_map.get(level.lower(), 'info')
            
            return {
                'ipAddress': LogParser._extract_ip(raw_log),
                'severity': severity,
                'message': message.strip(),
                'format': 'windows_event',
                'event_id': event_id
            }
        return None
    
    @staticmethod
    def _parse_firewall(raw_log: str):
        """
        Parse firewall logs (pfSense, iptables, etc.)
        Examples:
        - iptables: IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
        - pfSense: TCP:S SRC=192.168.1.100:12345 DST=10.0.0.1:80 [BLOCKED]
        """
        # iptables pattern
        iptables_pattern = r'SRC=([\d.]+)\s+DST=([\d.]+).*?DPT=(\d+)'
        match = re.search(iptables_pattern, raw_log)
        if match:
            src_ip, dst_ip, dst_port = match.groups()
            
            # Check if blocked/dropped
            if re.search(r'\b(block|drop|deny|reject)\b', raw_log, re.IGNORECASE):
                severity = 'warning'
                action = 'BLOCKED'
            else:
                severity = 'info'
                action = 'ALLOWED'
            
            message = f"Firewall {action}: {src_ip} → {dst_ip}:{dst_port}"
            
            return {
                'ipAddress': src_ip,
                'severity': severity,
                'message': message,
                'format': 'firewall',
                'dst_ip': dst_ip,
                'dst_port': dst_port
            }
        
        # Generic firewall format with BLOCKED/DROPPED
        if re.search(r'\b(block|drop|deny|reject)\b', raw_log, re.IGNORECASE):
            return {
                'ipAddress': LogParser._extract_ip(raw_log),
                'severity': 'warning',
                'message': raw_log.strip(),
                'format': 'firewall'
            }
        
        return None
    
    @staticmethod
    def _parse_generic(raw_log: str) -> dict:
        """
        Generic parser for unrecognized formats.
        Extracts IP and determines severity by keywords.
        """
        parsing_data = {
            'ipAddress': LogParser._extract_ip(raw_log),
            'severity': LogParser._determine_severity(raw_log),
            'message': raw_log.strip(),
            'format': 'generic'
        }
        
        # Remove leading timestamp-like prefix if present
        timestamp_pattern = r'^[\d\-:\s]+\s+'
        message = re.sub(timestamp_pattern, '', raw_log)
        parsing_data['message'] = message.strip()
        
        return parsing_data
    
    @staticmethod
    def _extract_ip(text: str):
        """Extract first IPv4 address from text."""
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        match = re.search(ip_pattern, text)
        return match.group() if match else None
    
    @staticmethod
    def _determine_severity(text: str):
        """Determine severity based on keywords in the text."""
        text_lower = text.lower()
        
        # Critical keywords
        if any(word in text_lower for word in ['critical', 'fatal', 'emergency', 'panic']):
            return 'critical'
        
        # Error keywords
        if any(word in text_lower for word in ['error', 'fail', 'denied', 'unauthorized', 'refused']):
            return 'error'
        
        # Warning keywords
        if any(word in text_lower for word in ['warn', 'warning', 'alert', 'notice']):
            return 'warning'
        
        # Default
        return 'info'


class BulkLogProcessor:
    """Handles processing of multiple logs at once (for file uploads)"""
    
    @staticmethod
    def process_bulk_logs(raw_logs_text, device_id):
        """
        Process multiple logs from a text block or file
        
        Args:
            raw_logs_text (str): Multiple log lines (separated by newlines)
            device_id (int): Device ID to associate logs with
            
        Returns:
            dict: Summary with success count, failed count, and created log entries
        """
        results = {
            'success': 0,
            'failed': 0,
            'log_entries': [],
            'errors': []
        }
        
        # Split by newlines and filter empty lines
        log_lines = [line.strip() for line in raw_logs_text.split('\n') if line.strip()]
        
        for line in log_lines:
            try:
                log_entry = LogCollector.collect_log(line, device_id)
                if log_entry:
                    results['success'] += 1
                    results['log_entries'].append(log_entry)
                else:
                    results['failed'] += 1
                    results['errors'].append(f"Failed to process: {line[:50]}...")
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(f"Error: {str(e)[:50]}")
        
        return results


class LogProcessor:
    """Analyzes logs for suspicious patterns and generates alerts"""
    
    # Threat detection patterns
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
    def process_log(log_entry):
        """
        Analyze a log entry for suspicious patterns and set flags/create alerts
        
        Args:
            log_entry (LogEntry): The log to analyze
        """
        try:
            message_lower = log_entry.message.lower()
            
            # First check basic severity-based flagging
            sev = (log_entry.severity or '').lower()
            if sev in ('critical', 'error'):
                log_entry.isFlagged = True
                log_entry.status = 'flagged'
                
                # Create a basic high-severity alert
                alert = Alert(
                    logID=log_entry.LogID,
                    alertType='High Severity Log',
                    severity=log_entry.severity.upper() if log_entry.severity else 'ERROR',
                    description=f"High severity log detected: {log_entry.message[:100]}",
                    status='pending'
                )
                db.session.add(alert)
            
            # Then check threat patterns
            for threat_type, patterns in LogProcessor.THREAT_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, message_lower):
                        # Threat detected!
                        log_entry.isFlagged = True
                        log_entry.status = 'flagged'
                        
                        # Determine severity
                        severity = LogProcessor._determine_severity(threat_type, log_entry.severity)
                        
                        # Create alert
                        alert = Alert(
                            logID=log_entry.LogID,
                            alertType=threat_type,
                            severity=severity,
                            description=f"{threat_type.replace('_', ' ')} detected: {log_entry.message[:100]}",
                            status='pending'
                        )
                        
                        db.session.add(alert)
                        # Only create one alert per log
                        db.session.commit()
                        return
            
            # If no threats detected, mark as analyzed
            if log_entry.status != 'flagged':
                log_entry.status = 'analyzed'
            
            db.session.commit()
            
        except Exception as e:
            # don't let processing crash the collector; log and continue
            print(f"Error processing log {getattr(log_entry, 'LogID', None)}: {e}")
            db.session.rollback()
    
    @staticmethod
    def _determine_severity(threat_type, log_severity):
        """Determine alert severity based on threat type and log severity"""
        severity_map = {
            'Failed_login': 'MEDIUM',
            'Unauthorized_access': 'HIGH',
            'Brute_force': 'CRITICAL',
            'Suspicious_activity': 'MEDIUM'
        }
        
        base_severity = severity_map.get(threat_type, 'LOW')
        
        # Escalate if log itself is critical
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
    """Login page - Admin authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate input
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        # Check if admin exists
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            # Successful login
            session['admin_id'] = admin.userID
            session['username'] = admin.username
            
            # Update last login time
            admin.lastLogin = datetime.now()
            db.session.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Failed login
            flash('Invalid username or password', 'error')
            return render_template('login.html')
    
    # GET request - show login form
    return render_template('login.html')

@app.route("/dashboard")
def dashboard():
    """Main dashboard - requires login"""
    if 'admin_id' not in session:
        flash('Please login to access the dashboard', 'error')
        return redirect(url_for('login'))
    
    # Get statistics for dashboard
    total_logs = LogEntry.query.count()
    active_alerts = Alert.query.filter_by(status='pending').count()
    devices_count = Device.query.count()
    flagged_logs = LogEntry.query.filter_by(isFlagged=True).count()
    
    username = session.get('username', 'Admin')
    return render_template('dashboard.html', 
                         username=username,
                         total_logs=total_logs,
                         active_alerts=active_alerts,
                         devices_count=devices_count,
                         flagged_logs=flagged_logs)

@app.route("/submit_log", methods=['GET', 'POST'])
def submit_log():
    """Submit logs manually - paste text or upload file"""
    if 'admin_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        device_id = request.form.get('device_id')
        log_text = request.form.get('log_text', '').strip()
        uploaded_file = request.files.get('log_file')
        
        # Validate device selection
        if not device_id:
            flash('Please select a device', 'error')
            return redirect(url_for('submit_log'))
        
        # Get log content from either text input or file
        log_content = None
        
        if uploaded_file and uploaded_file.filename:
            # File upload
            if uploaded_file.filename.endswith(('.log', '.txt')):
                log_content = uploaded_file.read().decode('utf-8', errors='ignore')
                flash(f'File "{uploaded_file.filename}" uploaded successfully', 'success')
            else:
                flash('Invalid file type. Please upload .log or .txt files', 'error')
                return redirect(url_for('submit_log'))
        elif log_text:
            # Text paste
            log_content = log_text
        else:
            flash('Please paste log text or upload a file', 'error')
            return redirect(url_for('submit_log'))
        
        # Process the logs
        if log_content:
            results = BulkLogProcessor.process_bulk_logs(log_content, int(device_id))
            
            if results['success'] > 0:
                flash(f'✅ Successfully processed {results["success"]} log(s)', 'success')
            if results['failed'] > 0:
                flash(f'⚠️ Failed to process {results["failed"]} log(s)', 'warning')
            
            return redirect(url_for('view_logs'))
    
    # GET request - show form
    devices = Device.query.all()
    return render_template('submit_log.html', devices=devices)

@app.route("/view_logs")
def view_logs():
    """View all logs with search and filter"""
    if 'admin_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    # Get filter parameters
    search_query: str = request.args.get('search', '').strip()
    device_id: int | None = request.args.get('device_id', type=int)
    severity: str = request.args.get('severity', '').strip()
    flagged_only: bool = request.args.get('flagged_only') == 'true'
    
    # Build query
    query = LogEntry.query
    
    # Apply filters
    if search_query:
        query = query.filter(LogEntry.message.contains(search_query))  # type: ignore[arg-type]
    
    if device_id:
        query = query.filter(LogEntry.sourceDevice == device_id)  # type: ignore[arg-type]
    
    if severity:
        query = query.filter(LogEntry.severity == severity)  # type: ignore[arg-type]
    
    if flagged_only:
        # Filter for flagged logs (where isFlagged is True)
        query = query.filter(LogEntry.isFlagged.is_(True))  # type: ignore[attr-defined]
    
    # Get logs ordered by most recent first
    logs = query.order_by(LogEntry.timestamp.desc()).all()
    
    # Get all devices for filter dropdown
    devices = Device.query.all()
    
    return render_template('view_logs.html', 
                         logs=logs,
                         devices=devices,
                         search_query=search_query,
                         selected_device=device_id,
                         selected_severity=severity,
                         flagged_only=flagged_only)

@app.route("/view_alerts")
def view_alerts():
    """View all security alerts"""
    if 'admin_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    # Get filter parameters
    status_filter: str = request.args.get('status', '').strip()
    severity_filter: str = request.args.get('severity', '').strip()
    alert_type_filter: str = request.args.get('alert_type', '').strip()
    
    # Build query
    query = Alert.query
    
    # Apply filters
    if status_filter:
        query = query.filter(Alert.status == status_filter)  # type: ignore[arg-type]
    
    if severity_filter:
        query = query.filter(Alert.severity == severity_filter)  # type: ignore[arg-type]
    
    if alert_type_filter:
        query = query.filter(Alert.alertType == alert_type_filter)  # type: ignore[arg-type]
    
    # Get alerts ordered by most recent first
    alerts = query.order_by(Alert.timestamp.desc()).all()
    
    return render_template('view_alerts.html',
                         alerts=alerts,
                         selected_status=status_filter,
                         selected_severity=severity_filter,
                         selected_alert_type=alert_type_filter)

@app.route("/acknowledge_alert/<int:alert_id>", methods=['POST'])
def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged"""
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    
    alert = Alert.query.get(alert_id)
    if alert:
        alert.status = 'acknowledged'
        db.session.commit()
        flash('Alert acknowledged', 'success')
    
    return redirect(url_for('view_alerts'))

@app.route("/resolve_alert/<int:alert_id>", methods=['POST'])
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
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
    """Logout - clear session"""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database and create default admin user"""
    with app.app_context():
        db.create_all()
        
        # Check if admin already exists
        if Admin.query.filter_by(username='admin').first() is None:
            # Create default admin user
            default_admin = Admin(
                username='admin',
                password=generate_password_hash('admin123')  # Default password
            )
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin user created: username='admin', password='admin123'")
        else:
            print("Admin user already exists")
        
        if Device.query.count() == 0: # if no devices exist, add some test devices
            test_devices = [
                Device(deviceName='Router-01', deviceType='router', ipAddress='192.168.1.1'),
                Device(deviceName='Firewall-01', deviceType='firewall', ipAddress='192.168.1.10'),
                Device(deviceName='Server-01', deviceType='server', ipAddress='192.168.1.100')
            ]
            for device in test_devices: # add each device to the session which is the database by the way kat
                db.session.add(device) #loop through and add
            db.session.commit() # save to database
            print("Test devices added to the database")
        else:
            print("Devices already exist in the database")

init_db()

            
# ==================== RUN APPLICATION ====================

if __name__ == "__main__":
    # Initialize database on first run   
    # Run the app
    app.run(debug=True)