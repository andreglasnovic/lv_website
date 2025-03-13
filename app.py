# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = 'lifevault_secret_key'  # Required for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lifevault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False)  # 'policyholder' or 'agent'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    applications = db.relationship('Application', backref='user', lazy=True)
    agent_links = db.relationship('AgentLink', backref='agent', lazy=True)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    insurance_carrier = db.Column(db.String(100))
    policy_type = db.Column(db.String(100))
    death_benefit = db.Column(db.Float)
    policy_issue_date = db.Column(db.Date)
    existing_loan = db.Column(db.Float, default=0)
    issue_class = db.Column(db.String(100))
    health_rating = db.Column(db.Integer)
    alcohol_use = db.Column(db.String(50))
    smoking_status = db.Column(db.String(50))
    eligible = db.Column(db.Boolean)
    status = db.Column(db.String(50), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AgentLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    client_email = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already in use. Please use a different email or login.', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            name=name,
            role=role
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log the user in
        login_user(new_user)
        
        flash('Registration successful!', 'success')
        
        # Redirect based on role
        if role == 'agent':
            return redirect(url_for('agent_dashboard'))
        else:
            if 'application_id' in session:
                return redirect(url_for('results'))
            return redirect(url_for('qualify'))
    
    # Check if there's a token (for agent invites)
    token = request.args.get('token')
    client_email = None
    
    if token:
        link = AgentLink.query.filter_by(token=token, used=False).first()
        if link:
            client_email = link.client_email
    
    return render_template('register.html', client_email=client_email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            
            # Redirect based on role
            if user.role == 'agent':
                return redirect(url_for('agent_dashboard'))
            else:
                # Check if user has existing applications
                applications = Application.query.filter_by(user_id=user.id).all()
                if applications:
                    return redirect(url_for('policyholder_dashboard'))
                else:
                    return redirect(url_for('qualify'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/policyholder-dashboard')
@login_required
def policyholder_dashboard():
    if current_user.role != 'policyholder':
        flash('Access denied. You must be a policyholder to view this page.', 'danger')
        return redirect(url_for('index'))
    
    # Get user's applications
    applications = Application.query.filter_by(user_id=current_user.id).order_by(Application.created_at.desc()).all()
    
    return render_template('policyholder_dashboard.html', applications=applications)

@app.route('/agent-dashboard')
@login_required
def agent_dashboard():
    if current_user.role != 'agent':
        flash('Access denied. You must be an agent to view this page.', 'danger')
        return redirect(url_for('index'))
    
    # Get agent's links
    links = AgentLink.query.filter_by(agent_id=current_user.id).order_by(AgentLink.created_at.desc()).all()
    
    return render_template('agent_dashboard.html', links=links)

@app.route('/qualify', methods=['GET', 'POST'])
def qualify():
    if request.method == 'POST':
        role = request.form.get('role')
        
        if role == 'policyholder':
            return redirect(url_for('policy_info'))
        elif role == 'agent':
            if current_user.is_authenticated and current_user.role == 'agent':
                return redirect(url_for('agent_dashboard'))
            else:
                # Prompt to create an agent account
                return redirect(url_for('register', role='agent'))
    
    return render_template('qualify.html')

@app.route('/agent', methods=['GET', 'POST'])
@login_required
def agent():
    if current_user.role != 'agent':
        flash('You must be registered as an agent to access this feature.', 'warning')
        return redirect(url_for('register', role='agent'))
        
    if request.method == 'POST':
        client_email = request.form.get('client_email')
        
        # Generate unique token for the link
        token = str(uuid.uuid4())
        
        # Save the link to database
        new_link = AgentLink(
            agent_id=current_user.id,
            client_email=client_email,
            token=token
        )
        
        db.session.add(new_link)
        db.session.commit()
        
        # Here we would send an email with the link
        # For now, we'll just simulate it
        application_link = url_for('register', token=token, _external=True)
        
        flash(f'Link sent to {client_email}!', 'success')
        return render_template('agent_confirmation.html', email=client_email, link=application_link)
    
    return render_template('agent.html')

@app.route('/policy-info', methods=['GET', 'POST'])
def policy_info():
    # Check if there's a token in the URL (coming from agent link)
    token = request.args.get('token')
    if token:
        link = AgentLink.query.filter_by(token=token, used=False).first()
        if link:
            session['agent_link_id'] = link.id
    
    if request.method == 'POST':
        # Store policy information in session
        session['insurance_carrier'] = request.form.get('insurance_carrier')
        session['policy_type'] = request.form.get('policy_type')
        session['death_benefit'] = request.form.get('death_benefit')
        session['policy_issue_date'] = request.form.get('policy_issue_date')
        session['existing_loan'] = request.form.get('existing_loan')
        session['issue_class'] = request.form.get('issue_class')
        
        return redirect(url_for('health_info'))
    
    return render_template('policy_info.html')

@app.route('/health-info', methods=['GET', 'POST'])
def health_info():
    # Check if policy info is in session
    if not all(key in session for key in ['insurance_carrier', 'policy_type', 'death_benefit', 'policy_issue_date', 'issue_class']):
        flash('Please complete the policy information first.', 'warning')
        return redirect(url_for('policy_info'))
    
    if request.method == 'POST':
        # Store health information in session
        session['health_rating'] = int(request.form.get('health_rating'))
        session['alcohol_use'] = request.form.get('alcohol_use')
        session['smoking_status'] = request.form.get('smoking_status')
        
        # Convert death benefit and existing loan to float
        death_benefit = float(session.get('death_benefit', 0))
        existing_loan = float(session.get('existing_loan', 0))
        
        # Convert policy issue date to datetime
        policy_issue_date = datetime.strptime(session.get('policy_issue_date'), '%Y-%m-%d').date()
        
        # Determine eligibility
        health_rating = session['health_rating']
        issue_class = session['issue_class']
        
        # Eligible if health rating is not 1 (not super healthy) and issue class is not Preferred
        eligible = True#(health_rating != 1) and (issue_class != 'Preferred')
        
        # If user is logged in, save the application
        if current_user.is_authenticated:
            application = Application(
                user_id=current_user.id,
                insurance_carrier=session['insurance_carrier'],
                policy_type=session['policy_type'],
                death_benefit=death_benefit,
                policy_issue_date=policy_issue_date,
                existing_loan=existing_loan,
                issue_class=issue_class,
                health_rating=health_rating,
                alcohol_use=session['alcohol_use'],
                smoking_status=session['smoking_status'],
                eligible=eligible
            )
            
            db.session.add(application)
            db.session.commit()
            
            # Store application id in session
            session['application_id'] = application.id
            
            # If this was from an agent link, mark it as used
            if 'agent_link_id' in session:
                link = AgentLink.query.get(session['agent_link_id'])
                if link:
                    link.used = True
                    db.session.commit()
                    session.pop('agent_link_id')
        else:
            # Store eligibility in session for non-logged in users
            session['eligible'] = eligible
        
        return redirect(url_for('results'))
    
    return render_template('health_info.html')

@app.route('/results')
def results():
    # Check if health info is in session
    if not all(key in session for key in ['health_rating', 'alcohol_use', 'smoking_status']):
        flash('Please complete the health information first.', 'warning')
        return redirect(url_for('health_info'))
    
    # Get eligibility
    if 'application_id' in session:
        # Get from database if user is logged in
        application = Application.query.get(session['application_id'])
        if application:
            eligible = application.eligible
        else:
            eligible = session.get('eligible', False)
    else:
        # Get from session for non-logged in users
        eligible = session.get('eligible', False)
    
    # If user is not logged in, prompt to create an account
    show_register = not current_user.is_authenticated
    
    return render_template('results.html', eligible=eligible, show_register=show_register)

@app.route('/next-steps')
def next_steps():
    # Check if user is logged in
    if not current_user.is_authenticated:
        flash('Please create an account to continue.', 'info')
        return redirect(url_for('register', role='policyholder'))
    
    return render_template('next_steps.html')

@app.route('/application/<int:application_id>')
@login_required
def application_detail(application_id):
    # Get application
    application = Application.query.get_or_404(application_id)
    
    # Check if user owns this application or is an admin
    if application.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this application.', 'danger')
        return redirect(url_for('policyholder_dashboard'))
    
    return render_template('application_detail.html', application=application)

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)