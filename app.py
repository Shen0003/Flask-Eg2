from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Email
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Secret key for sessions
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Initialize the database
def init_db():
    conn = sqlite3.connect('platform.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            instructor_id INTEGER,
            FOREIGN KEY (instructor_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

# Flask-WTForms for Login and Register
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])

# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('platform.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[4])  # id, username, email, role
    return None

# Routes for the platform

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = sqlite3.connect('platform.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            login_user(User(user[0], user[1], user[2], user[4]))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        conn = sqlite3.connect('platform.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', 
                       (username, email, password, 'student'))  # Default role as 'student'
        conn.commit()
        conn.close()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'instructor':
        return render_template('instructor_dashboard.html')
    return render_template('student_dashboard.html')

@app.route('/add_course', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.role != 'instructor':
        flash('You must be an instructor to create courses.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        conn = sqlite3.connect('platform.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO courses (title, description, instructor_id) VALUES (?, ?, ?)', 
                       (title, description, current_user.id))
        conn.commit()
        conn.close()
        flash('Course created successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_course.html')

@app.route('/')
def index():
    conn = sqlite3.connect('platform.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM courses')
    courses = cursor.fetchall()
    conn.close()
    return render_template('index.html', courses=courses)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
