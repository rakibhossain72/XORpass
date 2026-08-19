import os
import re
import secrets
import string
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from databases import Mongo
import encryption

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-enterprise-secret-key-change-in-prod')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect(app)

# Database
MONGO_URI = os.environ.get('MONGO_URI', "mongodb://localhost:27017")
client = Mongo(MONGO_URI)

# Password strength checker
def password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()-+=]", password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"

# Password Generator Helper
def generate_random_password(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
    chars = ""
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-+=_[]{}|;:,.<>?"
    if not chars:
        chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

# Routes
@app.route('/', methods=['GET'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = client.get_user(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    data = client.get_data(session['user_id'])
    return render_template('home.html', user=user, data=data)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect('/')
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        db_user = client.get_user(email)
        if db_user and check_password_hash(db_user['password'], password):
            session['user_id'] = email
            return redirect('/')
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect('/')
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm-password', '')
        
        if not email:
            flash('Email is required', 'danger')
            return redirect('/signup')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect('/signup')
        
        elif len(password) < 8 or len(password) > 64:
            flash('Password must be between 8 and 64 characters long', 'danger')
            return redirect('/signup')
        
        elif not any(char.isdigit() for char in password):
            flash('Password must contain at least one number', 'danger')
            return redirect('/signup')
        
        elif not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect('/signup')
        
        elif not any(char.islower() for char in password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect('/signup')
        
        elif any(char.isspace() for char in password):
            flash('Password must not contain any spaces', 'danger')
            return redirect('/signup')
        
        if client.get_user(email):
            flash('Email already exists', 'danger')
            return redirect('/signup')
        else:
            # Generating Private & Public Key
            public_key, private_key = encryption.encode_key(password)
            password_hash = generate_password_hash(password)
            client.add_user(password_hash, email, public_key, private_key)
            session['user_id'] = email
            return redirect('/')
    return render_template('signup.html')

# Add
@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        website = request.form.get('website', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        owner_id = session['user_id']
        
        user_data = client.get_user(session['user_id'])
        if not user_data:
            session.pop('user_id', None)
            return redirect(url_for('login'))

        # Validation
        data = client.get_data(owner_id)
        if data:
            for d in data:
                if d['website'] == website and d['email'] == email:
                    flash('An entry for this website and email already exists', 'danger')
                    return redirect(url_for('add'))
                
        encrypted_password = encryption.encode_data(password, user_data['public_key'])
        difficulty = password_strength(password)
        client.add_data(website, email, encrypted_password, owner_id, difficulty)
        flash('Password added successfully', 'success')
        return redirect('/')
    return render_template('add.html')

# Edit
@app.route('/edit', methods=['GET', 'POST'])
def tedit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        id = request.form.get('id')
        password = request.form.get('password')

        data = client.get_by_id(id)
        if not data or data.get('owner_id') != session['user_id']:
            flash('Unauthorized access or entry not found', 'danger')
            return redirect('/')

        user_data = client.get_user(session['user_id'])
        if not user_data or not check_password_hash(user_data['password'], password):
            flash('Invalid master password', 'danger')
            return redirect(f'/decrypt/{id}')

        try:
            decoded_key = encryption.decode_key(user_data['private_key'], password)
            data['password'] = encryption.decode_data(data['password'], decoded_key)
        except Exception:
            flash('Failed to decrypt stored password. Master password may be incorrect.', 'danger')
            return redirect(f'/decrypt/{id}')

        return render_template('edit.html', data=data)
    return redirect('/')

@app.route('/edit/<string:doc_id>', methods=['POST'])
def update(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    data = client.get_by_id(doc_id)
    if not data or data.get('owner_id') != session['user_id']:
        flash('Unauthorized access or entry not found', 'danger')
        return redirect('/')

    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    website = request.form.get('website', '').strip()
    user_data = client.get_user(session['user_id'])

    encrypted_password = encryption.encode_data(password, user_data['public_key'])
    difficulty = password_strength(password)

    updated_fields = {
        'website': website,
        'email': email,
        'password': encrypted_password,
        'difficulty': difficulty,
        'owner_id': session['user_id']
    }
    client.update_by_id(doc_id, updated_fields)
    flash('Password updated successfully', 'success')
    return redirect('/')

# Decrypt
@app.route('/decrypt/<string:doc_id>', methods=['GET', 'POST'])
def decrypt(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    data = client.get_by_id(doc_id)
    if not data or data.get('owner_id') != session['user_id']:
        flash('Unauthorized access or entry not found', 'danger')
        return redirect('/')

    if request.method == 'POST':
        password = request.form.get('password', '')
        user_data = client.get_user(session['user_id'])
        if not user_data or not check_password_hash(user_data['password'], password):
            flash('Invalid password', 'danger')
            return redirect(url_for('decrypt', doc_id=doc_id))

        # Render tedit logic
        try:
            decoded_key = encryption.decode_key(user_data['private_key'], password)
            data['password'] = encryption.decode_data(data['password'], decoded_key)
        except Exception:
            flash('Failed to decrypt password', 'danger')
            return redirect(url_for('decrypt', doc_id=doc_id))

        return render_template('edit.html', data=data)

    return render_template('decrypt.html', id=doc_id)

# Delete
@app.route('/delete', methods=['POST'])
def delete():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    id = request.form.get('id')
    data = client.get_by_id(id)
    if not data or data.get('owner_id') != session['user_id']:
        flash('Unauthorized access or entry not found', 'danger')
        return redirect('/')

    client.delete_data(id)
    flash('Password deleted successfully', 'success')
    return redirect('/')

# Settings
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == 'POST':
        password = request.form.get('password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_new_password', '')

        user_data = client.get_user(session['user_id'])
        if not user_data or not check_password_hash(user_data['password'], password):
            flash('Invalid current password', 'danger')
            return redirect('/settings')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect('/settings')
        
        elif len(new_password) < 8 or len(new_password) > 64:
            flash('Password must be between 8 and 64 characters long', 'danger')
            return redirect('/settings')
        
        elif not any(char.isdigit() for char in new_password):
            flash('Password must contain at least one number', 'danger')
            return redirect('/settings')
        
        elif not any(char.isupper() for char in new_password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect('/settings')
        
        elif not any(char.islower() for char in new_password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect('/settings')
        
        elif any(char.isspace() for char in new_password):
            flash('Password must not contain any spaces', 'danger')
            return redirect('/settings')
        
        elif new_password == password:
            flash('New password cannot be the same as the old password', 'danger')
            return redirect('/settings')
        else:
            try:
                private_key = encryption.decode_key(user_data['private_key'], password)
                user_data['private_key'] = encryption.encode_key(new_password, private_key=private_key)[1]
                user_data['password'] = generate_password_hash(new_password)
                client.update_user(session['user_id'], user_data)
                flash('Master password updated successfully', 'success')
                return redirect('/')
            except Exception:
                flash('Failed to update master password', 'danger')
                return redirect('/settings')

    return render_template('settings.html')

# Generate Password Endpoint
@app.route('/generate-password', methods=['GET'])
def generate_password_api():
    length = request.args.get('length', 16, type=int)
    length = max(8, min(length, 64))
    symbols = request.args.get('symbols', 'true').lower() == 'true'
    numbers = request.args.get('numbers', 'true').lower() == 'true'
    uppercase = request.args.get('uppercase', 'true').lower() == 'true'
    lowercase = request.args.get('lowercase', 'true').lower() == 'true'

    pwd = generate_random_password(
        length=length,
        use_uppercase=uppercase,
        use_lowercase=lowercase,
        use_digits=numbers,
        use_symbols=symbols
    )
    return jsonify({'password': pwd})

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)
