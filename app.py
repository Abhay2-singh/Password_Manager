from flask import Flask, render_template, redirect, request, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from models import db, User, PasswordEntry
from encryption_util import encrypt_password, decrypt_password
import os

app = Flask(__name__)
app.secret_key = 'SuperSecretKey'

# Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# ✅ Create DB with app context (run once during app launch)
with app.app_context():
    db.create_all()

# ✅ Inject decrypt_password into Jinja templates
@app.context_processor
def inject_utilities():
    return dict(decrypt_password=decrypt_password)

# ---------- Routes ----------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access dashboard.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']

        try:
            encrypted_pass = encrypt_password(password)
            
            new_entry = PasswordEntry(
                service=service,
                username=username,
                password=encrypted_pass,
                user_id=session['user_id']
            )
            db.session.add(new_entry)
            db.session.commit()
            flash('Password saved successfully!')
        except Exception as e:
            flash(f'Error saving password: {str(e)}')
            print(f'Encryption error: {str(e)}')

    # Fetch entries and decrypt passwords before display
    entries = PasswordEntry.query.filter_by(user_id=session['user_id']).all()

    decrypted_entries = []
    for entry in entries:
        # Decryption is now handled in the decrypt_password function with try/except
        decrypted_password = decrypt_password(entry.password)
        decrypted_entries.append({
            'id': entry.id,
            'service': entry.service,
            'username': entry.username,
            'password': decrypted_password
        })

    return render_template('dashboard.html', entries=decrypted_entries)

@app.route('/delete_entry/<int:id>')
def delete_entry(id):
    entry = PasswordEntry.query.get_or_404(id)
    if entry.user_id != session.get('user_id'):
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('dashboard'))

    db.session.delete(entry)
    db.session.commit()
    flash('Password entry deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/edit_entry/<int:id>', methods=['GET', 'POST'])
def edit_entry(id):
    entry = PasswordEntry.query.get_or_404(id)
    if entry.user_id != session.get('user_id'):
        flash('You do not have permission to edit this entry.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entry.service = request.form['service']
        entry.username = request.form['username']
        try:
            entry.password = encrypt_password(request.form['password'])
            db.session.commit()
            flash('Password entry updated successfully.')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error updating password: {str(e)}')
            print(f'Encryption error during update: {str(e)}')
            # Roll back the session to avoid partial updates
            db.session.rollback()
            return redirect(url_for('dashboard'))

    try:
        decrypted_password = decrypt_password(entry.password)
    except Exception as e:
        # If decryption fails, show a placeholder
        decrypted_password = ""
        flash('Could not decrypt the existing password. Please enter a new one.')
    
    return render_template('edit_entry.html', entry=entry, password=decrypted_password)

# ---------- Run ----------
if __name__ == '__main__':
    app.run(debug=True, port=7000)
