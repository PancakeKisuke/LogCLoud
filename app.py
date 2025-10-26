# imports
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

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
Scss(app, static_dir='static', asset_dir='static')
  
# ==================== DATABASE TABLES ====================
# this section defines the database tables for all my classes

class Admin(db.Model):
    __tablename__ = 'admin'
    
    userID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    lastLogin = db.Column(db.DateTime, nullable=True)
    
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
    
    def __repr__(self):
        return f'<Alert {self.alertID} - {self.alertType} ({self.severity})>' # useful for debugging

# ==================== LOGIC CLASSES ====================

# ==================== LOGIC CLASSES ====================

import re


class LogCollector:
    """Class to handle log collection from devices"""

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

            parsed_data = LogParser.parse_log(raw_log)

            # Create the LogEntry and persist it so it has a primary key
            log_entry = LogEntry(
                sourceDevice=device_id,
                ipAddress=parsed_data.get('ipAddress'),
                severity=parsed_data.get('severity', 'info'),
                message=parsed_data.get('message', raw_log),
                rawlog=raw_log,
                status='parsed'
            )

            db.session.add(log_entry)
            db.session.commit()  # now log_entry.LogID is available

            # Process the log (may create alerts, update flags, etc.)
            LogProcessor.analyze(log_entry)

            return log_entry

        except Exception as e:
            print(f"Error collecting log: {e}")
            db.session.rollback()
            return None


class LogParser:
    """Parses raw log data into a simple structured format."""

    @staticmethod
    def parse_log(raw_log: str) -> dict:
        parsing_data = {
            'ipAddress': None,
            'severity': 'info',
            'message': raw_log,
        }

        # Extract IPv4 address if present
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ip_match = re.search(ip_pattern, raw_log)
        if ip_match:
            parsing_data['ipAddress'] = ip_match.group()

        # Determine severity by keywords
        raw_lower = raw_log.lower()
        if 'critical' in raw_lower or 'fatal' in raw_lower:
            parsing_data['severity'] = 'critical'
        elif 'error' in raw_lower or 'fail' in raw_lower:
            parsing_data['severity'] = 'error'
        elif 'warn' in raw_lower:
            parsing_data['severity'] = 'warning'
        else:
            parsing_data['severity'] = 'info'

        # Remove leading timestamp-like prefix if present
        timestamp_pattern = r'^[\d\-:\s]+\s+'
        message = re.sub(timestamp_pattern, '', raw_log)
        parsing_data['message'] = message.strip()

        return parsing_data


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
    def analyze(log_entry):
        """
        Analyze a log entry for suspicious patterns
        
        Args:
            log_entry (LogEntry): The log to analyze
        """
        message_lower = log_entry.message.lower()
        
        # Check each threat pattern
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
                        description=f"{threat_type} detected: {log_entry.message[:100]}",
                        status='pending'
                    )
                    
                    db.session.add(alert)
                    return  # Only create one alert per log
        
        # No threats detected
        log_entry.status = 'analyzed'
    
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
            from datetime import datetime
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
    
    username = session.get('username', 'Admin')
    return render_template('dashboard.html', username=username)

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
            test_device = [
                Device(deviceName='Router-01', deviceType='router', ipAddress='192.168.1.1'),
                Device(deviceName='Firewall-01', deviceType='firewall', ipAddress='192.168.1.10'),
                Device(deviceName='Server-01', deviceType='server', ipAddress='192.168.1.100')
            ]
            for device in test_device: # add each device to the session which is the database by the way kat
                db.session.add(device) #loop through and add
            db.session.commit() # save to database
            print("Test devices added to the database")
        else:
            print("Devices already exist in the database")
            
# ==================== RUN APPLICATION ====================

if __name__ == "__main__":
    # Initialize database on first run
    init_db()
    
    # Run the app
    app.run(debug=True)

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
            from datetime import datetime
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
    
    username = session.get('username', 'Admin')
    return render_template('dashboard.html', username=username)

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
            test_device = [
                Device(deviceName='Router-01', deviceType='router', ipAddress='192.168.1.1'),
                Device(deviceName='Firewall-01', deviceType='firewall', ipAddress='192.168.1.10'),
                Device(deviceName='Server-01', deviceType='server', ipAddress='192.168.1.100')
            ]
            for device in test_device: # add each device to the session which is the database by the way kat
                db.session.add(device) #loop through and add
            db.session.commit() # save to database
            print("Test devices added to the database")
        else:
            print("Devices already exist in the database")
            
# ==================== RUN APPLICATION ====================

if __name__ == "__main__":
    # Initialize database on first run
    init_db()
    
    # Run the app
    app.run(debug=True)