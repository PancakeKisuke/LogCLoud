# imports
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# My webapp
app = Flask(__name__)

# Secret key for sessions (IMPORTANT: Change this to a random string in production)
app.secret_key = 'your-secret-key-change-this-in-production'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logcloud.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Compile SCSS
Scss(app, static_dir='static', asset_dir='static')

# ==================== DATABASE MODELS ====================

class Admin(db.Model):
    __tablename__ = 'admin'
    
    userID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    lastLogin = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<Admin {self.username}>'

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

# ==================== RUN APPLICATION ====================

if __name__ == "__main__":
    # Initialize database on first run
    init_db()
    
    # Run the app
    app.run(debug=True)