# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'lifevault_secret_key'  # Required for session management

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qualify', methods=['GET', 'POST'])
def qualify():
    if request.method == 'POST':
        role = request.form.get('role')
        
        if role == 'policyholder':
            return redirect(url_for('policy_info'))
        elif role == 'agent':
            return render_template('agent.html')
    
    return render_template('qualify.html')

@app.route('/agent', methods=['GET', 'POST'])
def agent():
    if request.method == 'POST':
        client_email = request.form.get('client_email')
        # In a real app, we would send an email here
        flash(f'Link sent to {client_email}!', 'success')
        return render_template('agent_confirmation.html', email=client_email)
    
    return render_template('agent.html')

@app.route('/policy-info', methods=['GET', 'POST'])
def policy_info():
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
    if request.method == 'POST':
        # Store health information in session
        session['health_rating'] = int(request.form.get('health_rating'))
        session['alcohol_use'] = request.form.get('alcohol_use')
        session['smoking_status'] = request.form.get('smoking_status')
        
        return redirect(url_for('results'))
    
    return render_template('health_info.html')

@app.route('/results')
def results():
    # Determine eligibility
    health_rating = session.get('health_rating')
    issue_class = session.get('issue_class')
    
    # Eligible if health rating is not 1 (not super healthy) and issue class is not Preferred
    eligible = True
    
    return render_template('results.html', eligible=eligible)

@app.route('/next-steps')
def next_steps():
    return render_template('next_steps.html')

if __name__ == '__main__':
    app.run(debug=True)