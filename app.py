from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///new_eventease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)  # 'student', 'faculty', 'admin'
    
    # Add relationships
    created_events = db.relationship('Event', backref='creator', foreign_keys='Event.created_by')
    approved_events = db.relationship('Event', backref='approver', foreign_keys='Event.approved_by')
    mentored_events = db.relationship('Event', backref='mentor', foreign_keys='Event.mentor_id')
    registrations = db.relationship('Registration', backref='user', lazy=True)
    feedback = db.relationship('Feedback', backref='user', lazy=True)
    certificate_requests = db.relationship('CertificateRequest', backref='user', foreign_keys='CertificateRequest.user_id', lazy=True)
    approved_certificates = db.relationship('CertificateRequest', backref='approver', foreign_keys='CertificateRequest.approved_by', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    venue = db.Column(db.String(100), nullable=False)
    max_participants = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approval_date = db.Column(db.DateTime)
    approval_comments = db.Column(db.Text)
    
    # Add relationships
    registrations = db.relationship('Registration', backref='event', lazy=True)
    feedback = db.relationship('Feedback', backref='event', lazy=True)
    certificate_requests = db.relationship('CertificateRequest', backref='event', lazy=True)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    attendance = db.Column(db.Boolean, default=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)

class CertificateRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approval_date = db.Column(db.DateTime)
    approval_comments = db.Column(db.Text)

class Venue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='available')  # available, maintenance, booked
    facilities = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OverseasLogistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    venue = db.Column(db.String(200), nullable=False)
    travel_arrangements = db.Column(db.Text)
    accommodation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SoundSystem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    system_type = db.Column(db.String(50), nullable=False)  # basic, advanced, professional
    status = db.Column(db.String(20), default='available')  # available, in_use, maintenance
    location = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Catering(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    catering_type = db.Column(db.String(50), nullable=False)  # buffet, plated, cocktail
    menu_type = db.Column(db.String(50), nullable=False)  # vegetarian, non_vegetarian, vegan
    guest_count = db.Column(db.Integer, nullable=False)
    special_requirements = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecurityPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    security_level = db.Column(db.String(50), nullable=False)  # basic, standard, high, vip
    personnel_count = db.Column(db.Integer, nullable=False)
    equipment = db.Column(db.Text)  # JSON string of selected equipment
    security_plan = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    # Get upcoming events (events that haven't happened yet)
    upcoming_events = Event.query.filter(Event.date > datetime.utcnow()).order_by(Event.date.asc()).limit(5).all()
    return render_template('index.html', events=upcoming_events)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        events = Event.query.filter_by(created_by=current_user.id).all()
        registered_events = Registration.query.filter_by(user_id=current_user.id).all()
        return render_template('student_dashboard.html', events=events, registered_events=registered_events)
    elif current_user.role == 'faculty':
        pending_events = Event.query.filter_by(status='pending').all()
        return render_template('faculty_dashboard.html', pending_events=pending_events)
    else:  # admin
        events = Event.query.all()
        return render_template('admin_dashboard.html', events=events)

@app.route('/propose_event', methods=['GET', 'POST'])
@login_required
def propose_event():
    if current_user.role != 'student':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date = datetime.strptime(request.form.get('date'), '%Y-%m-%dT%H:%M')
        venue = request.form.get('venue')
        max_participants = request.form.get('max_participants')
        
        event = Event(
            title=title,
            description=description,
            date=date,
            venue=venue,
            max_participants=max_participants,
            created_by=current_user.id,
            created_at=datetime.utcnow()
        )
        
        db.session.add(event)
        db.session.commit()
        flash('Event proposed successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('propose_event.html')

ADMIN_ACCESS_CODE = "admin123"  # In production, this should be stored securely

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another email or login.', 'danger')
            return redirect(url_for('register'))
        
        # Validate password
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))
        
        # Handle admin registration
        if role == 'admin':
            admin_code = request.form.get('admin_code')
            if not admin_code or admin_code != ADMIN_ACCESS_CODE:
                flash('Invalid admin access code.', 'danger')
                return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('dashboard'))
    
    # Get upcoming events
    upcoming_events = Event.query.filter(
        Event.date > datetime.utcnow(),
        Event.status == 'approved'
    ).order_by(Event.date.asc()).limit(5).all()
    
    # Get recent feedback
    recent_feedback = Feedback.query.filter_by(
        user_id=current_user.id
    ).order_by(Feedback.submission_date.desc()).limit(5).all()
    
    return render_template('student_dashboard.html',
                         upcoming_events=upcoming_events,
                         recent_feedback=recent_feedback)

@app.route('/events')
@login_required
def view_events():
    events = Event.query.filter(
        Event.status == 'approved',
        Event.date > datetime.utcnow()
    ).order_by(Event.date.asc()).all()
    return render_template('events.html', events=events)

@app.route('/events/<int:event_id>')
@login_required
def event_details(event_id):
    event = Event.query.get_or_404(event_id)
    registration = None
    if current_user.role == 'student':
        registration = Registration.query.filter_by(
            event_id=event_id,
            user_id=current_user.id
        ).first()
    is_registered = registration is not None
    return render_template('event_details.html', 
                         event=event, 
                         is_registered=is_registered,
                         registration=registration,
                         now=datetime.utcnow())

@app.route('/events/<int:event_id>/register', methods=['POST'])
@login_required
def register_for_event(event_id):
    if current_user.role != 'student':
        flash('Only students can register for events.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))
    
    event = Event.query.get_or_404(event_id)
    
    # Check if already registered
    if Registration.query.filter_by(
        event_id=event_id,
        user_id=current_user.id
    ).first():
        flash('You are already registered for this event.', 'warning')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Check if event is full
    current_registrations = Registration.query.filter_by(event_id=event_id).count()
    if current_registrations >= event.max_participants:
        flash('This event is full.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Create registration
    registration = Registration(
        event_id=event_id,
        user_id=current_user.id,
        registration_date=datetime.utcnow()
    )
    
    try:
        db.session.add(registration)
        db.session.commit()
        flash('Successfully registered for the event!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while registering. Please try again.', 'danger')
    
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/certificates/request', methods=['GET', 'POST'])
@login_required
def request_certificate():
    if current_user.role != 'student':
        flash('Only students can request certificates.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        event_id = request.form.get('event_id', type=int)
        event = Event.query.get_or_404(event_id)
        
        # Check if user attended the event
        registration = Registration.query.filter_by(
            event_id=event_id,
            user_id=current_user.id,
            attendance=True
        ).first()
        
        if not registration:
            flash('You must attend the event to request a certificate.', 'danger')
            return redirect(url_for('request_certificate'))
        
        # Check if certificate already requested
        existing_request = CertificateRequest.query.filter_by(
            event_id=event_id,
            user_id=current_user.id
        ).first()
        
        if existing_request:
            flash('You have already requested a certificate for this event.', 'warning')
            return redirect(url_for('my_certificates'))
        
        # Create certificate request
        certificate_request = CertificateRequest(
            event_id=event_id,
            user_id=current_user.id,
            request_date=datetime.utcnow(),
            status='pending'
        )
        
        try:
            db.session.add(certificate_request)
            db.session.commit()
            flash('Certificate request submitted successfully!', 'success')
            return redirect(url_for('my_certificates'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting the request.', 'danger')
    
    # Get events where user attended
    attended_events = Event.query.join(Registration).filter(
        Registration.user_id == current_user.id,
        Registration.attendance == True
    ).all()
    
    return render_template('request_certificate.html', events=attended_events)

@app.route('/certificates/my')
@login_required
def my_certificates():
    if current_user.role != 'student':
        return redirect(url_for('dashboard'))
    
    certificate_requests = CertificateRequest.query.filter_by(
        user_id=current_user.id
    ).order_by(CertificateRequest.request_date.desc()).all()
    
    return render_template('my_certificates.html', certificate_requests=certificate_requests)

@app.route('/my_registrations')
@login_required
def my_registrations():
    if current_user.role != 'student':
        return redirect(url_for('dashboard'))
    
    # Get all registrations for the current user
    registrations = Registration.query.filter_by(
        user_id=current_user.id
    ).order_by(Registration.registration_date.desc()).all()
    
    # Separate registrations into upcoming and past events
    upcoming_registrations = []
    past_registrations = []
    
    for reg in registrations:
        if reg.event.date > datetime.utcnow():
            upcoming_registrations.append(reg)
        else:
            past_registrations.append(reg)
    
    return render_template('my_registrations.html',
                         upcoming_registrations=upcoming_registrations,
                         past_registrations=past_registrations)

@app.route('/faculty/dashboard')
@login_required
def faculty_dashboard():
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    # Get pending events for review
    pending_events = Event.query.filter_by(status='pending').order_by(Event.created_at.desc()).all()
    
    # Get recent feedback
    recent_feedback = Feedback.query.order_by(Feedback.submission_date.desc()).limit(5).all()
    
    return render_template('faculty_dashboard.html',
                         pending_events=pending_events,
                         recent_feedback=recent_feedback)

@app.route('/events/review')
@login_required
def review_events():
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    pending_events = Event.query.filter_by(status='pending').order_by(Event.created_at.desc()).all()
    return render_template('review_events.html', events=pending_events)

@app.route('/events/<int:event_id>/review', methods=['GET', 'POST'])
@login_required
def review_event(event_id):
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        comments = request.form.get('comments', '').strip()
        
        if action == 'approve':
            event.status = 'approved'
            event.approved_by = current_user.id
            event.approval_date = datetime.utcnow()
            event.approval_comments = comments
            flash('Event approved successfully!', 'success')
        elif action == 'reject':
            event.status = 'rejected'
            event.approved_by = current_user.id
            event.approval_date = datetime.utcnow()
            event.approval_comments = comments
            flash('Event rejected.', 'info')
        
        try:
            db.session.commit()
            return redirect(url_for('review_events'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while processing your request.', 'danger')
    
    return render_template('review_event.html', event=event)

@app.route('/events/assign-mentors')
@login_required
def assign_mentors():
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    # Get approved events without mentors
    events = Event.query.filter(
        Event.status == 'approved',
        Event.mentor_id.is_(None)
    ).order_by(Event.date.asc()).all()
    
    # Get available mentors (faculty members)
    mentors = User.query.filter_by(role='faculty').all()
    
    return render_template('assign_mentors.html', events=events, mentors=mentors)

@app.route('/events/<int:event_id>/assign-mentor', methods=['POST'])
@login_required
def assign_event_mentor(event_id):
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    event = Event.query.get_or_404(event_id)
    mentor_id = request.form.get('mentor_id', type=int)
    
    if not mentor_id:
        flash('Please select a mentor.', 'danger')
        return redirect(url_for('assign_mentors'))
    
    mentor = User.query.get_or_404(mentor_id)
    if mentor.role != 'faculty':
        flash('Selected user is not a faculty member.', 'danger')
        return redirect(url_for('assign_mentors'))
    
    event.mentor_id = mentor_id
    
    try:
        db.session.commit()
        flash('Mentor assigned successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while assigning the mentor.', 'danger')
    
    return redirect(url_for('assign_mentors'))

@app.route('/events/reports')
@login_required
def event_reports():
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    # Get event statistics
    total_events = Event.query.count()
    approved_events = Event.query.filter_by(status='approved').count()
    pending_events = Event.query.filter_by(status='pending').count()
    rejected_events = Event.query.filter_by(status='rejected').count()
    
    # Get attendance statistics
    total_registrations = Registration.query.count()
    total_attendance = Registration.query.filter_by(attendance=True).count()
    
    # Get feedback statistics
    total_feedback = Feedback.query.count()
    avg_rating = db.session.query(db.func.avg(Feedback.rating)).scalar() or 0
    
    return render_template('event_reports.html',
                         total_events=total_events,
                         approved_events=approved_events,
                         pending_events=pending_events,
                         rejected_events=rejected_events,
                         total_registrations=total_registrations,
                         total_attendance=total_attendance,
                         total_feedback=total_feedback,
                         avg_rating=avg_rating)

@app.route('/events/feedback')
@login_required
def view_feedback():
    if current_user.role != 'faculty':
        return redirect(url_for('dashboard'))
    
    # Get all feedback with pagination
    page = request.args.get('page', 1, type=int)
    feedback = Feedback.query.order_by(Feedback.submission_date.desc()).paginate(
        page=page, per_page=10, error_out=False)
    
    return render_template('view_feedback.html', feedback=feedback)

@app.route('/events/<int:event_id>/feedback', methods=['GET', 'POST'])
@login_required
def submit_feedback(event_id):
    if current_user.role != 'student':
        flash('Only students can submit feedback.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))
    
    event = Event.query.get_or_404(event_id)
    
    # Check if user attended the event
    registration = Registration.query.filter_by(
        event_id=event_id,
        user_id=current_user.id,
        attendance=True
    ).first()
    
    if not registration:
        flash('You must attend the event to submit feedback.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Check if feedback already submitted
    existing_feedback = Feedback.query.filter_by(
        event_id=event_id,
        user_id=current_user.id
    ).first()
    
    if request.method == 'POST':
        rating = request.form.get('rating', type=int)
        comment = request.form.get('comment', '').strip()
        
        if not rating or rating < 1 or rating > 5:
            flash('Please provide a valid rating.', 'danger')
            return redirect(url_for('submit_feedback', event_id=event_id))
        
        if existing_feedback:
            existing_feedback.rating = rating
            existing_feedback.comment = comment
            existing_feedback.submission_date = datetime.utcnow()
        else:
            feedback = Feedback(
                event_id=event_id,
                user_id=current_user.id,
                rating=rating,
                comment=comment
            )
            db.session.add(feedback)
        
        try:
            db.session.commit()
            flash('Feedback submitted successfully!', 'success')
            return redirect(url_for('event_details', event_id=event_id))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting feedback.', 'danger')
    
    return render_template('submit_feedback.html',
                         event=event,
                         existing_feedback=existing_feedback)

@app.route('/events/<int:event_id>/mark_attendance', methods=['POST'])
@login_required
def mark_attendance(event_id):
    if current_user.role != 'student':
        flash('Only students can mark attendance.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))
    
    event = Event.query.get_or_404(event_id)
    
    # Check if user is registered
    registration = Registration.query.filter_by(
        event_id=event_id,
        user_id=current_user.id
    ).first()
    
    if not registration:
        flash('You must be registered for the event to mark attendance.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Update attendance
    registration.attendance = True
    try:
        db.session.commit()
        flash('Attendance marked successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while marking attendance.', 'danger')
    
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/certificates/manage')
@login_required
def manage_certificates():
    if current_user.role != 'faculty':
        flash('Only faculty members can manage certificates.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all pending certificate requests
    pending_requests = CertificateRequest.query.filter_by(status='pending').all()
    approved_requests = CertificateRequest.query.filter_by(status='approved').all()
    rejected_requests = CertificateRequest.query.filter_by(status='rejected').all()
    
    return render_template('manage_certificates.html',
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         rejected_requests=rejected_requests)

@app.route('/certificates/<int:request_id>/approve', methods=['POST'])
@login_required
def approve_certificate(request_id):
    if current_user.role != 'faculty':
        flash('Only faculty members can approve certificates.', 'danger')
        return redirect(url_for('dashboard'))
    
    certificate_request = CertificateRequest.query.get_or_404(request_id)
    comments = request.form.get('comments', '').strip()
    
    certificate_request.status = 'approved'
    certificate_request.approved_by = current_user.id
    certificate_request.approval_date = datetime.utcnow()
    certificate_request.approval_comments = comments
    
    try:
        db.session.commit()
        flash('Certificate request approved successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while approving the certificate.', 'danger')
    
    return redirect(url_for('manage_certificates'))

@app.route('/certificates/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_certificate(request_id):
    if current_user.role != 'faculty':
        flash('Only faculty members can reject certificates.', 'danger')
        return redirect(url_for('dashboard'))
    
    certificate_request = CertificateRequest.query.get_or_404(request_id)
    comments = request.form.get('comments', '').strip()
    
    certificate_request.status = 'rejected'
    certificate_request.approved_by = current_user.id
    certificate_request.approval_date = datetime.utcnow()
    certificate_request.approval_comments = comments
    
    try:
        db.session.commit()
        flash('Certificate request rejected.', 'info')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while rejecting the certificate.', 'danger')
    
    return redirect(url_for('manage_certificates'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    # Get all data for the dashboard
    venues = Venue.query.all()
    overseas_logistics = OverseasLogistics.query.all()
    sound_systems = SoundSystem.query.all()
    catering_plans = Catering.query.all()
    security_plans = SecurityPlan.query.all()
    
    return render_template('admin_dashboard.html',
                         venues=venues,
                         overseas_logistics=overseas_logistics,
                         sound_systems=sound_systems,
                         catering_plans=catering_plans,
                         security_plans=security_plans)

# API Routes for Admin Management
@app.route('/api/venues', methods=['POST'])
@login_required
def add_venue():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    venue = Venue(
        name=data['name'],
        capacity=data['capacity'],
        status=data['status'],
        facilities=data['facilities']
    )
    
    try:
        db.session.add(venue)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/overseas-logistics', methods=['POST'])
@login_required
def add_overseas_logistics():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    logistics = OverseasLogistics(
        country=data['country'],
        city=data['city'],
        venue=data['venue'],
        travel_arrangements=data['travel'],
        accommodation=data['accommodation']
    )
    
    try:
        db.session.add(logistics)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/sound-systems', methods=['POST'])
@login_required
def add_sound_system():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    sound_system = SoundSystem(
        system_type=data['system'],
        status=data['status'],
        location=data['location']
    )
    
    try:
        db.session.add(sound_system)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/catering', methods=['POST'])
@login_required
def add_catering():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    catering = Catering(
        catering_type=data['catering'],
        menu_type=data['menu'],
        guest_count=data['guests'],
        special_requirements=data['requirements']
    )
    
    try:
        db.session.add(catering)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/security', methods=['POST'])
@login_required
def add_security_plan():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    security_plan = SecurityPlan(
        security_level=data['level'],
        personnel_count=data['personnel'],
        equipment=json.dumps(data['equipment']),
        security_plan=data['plan']
    )
    
    try:
        db.session.add(security_plan)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 