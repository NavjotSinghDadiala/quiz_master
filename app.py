from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
from models import *
import matplotlib.pyplot as plt
import io
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        
        if user:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['username'] = user.username
            session['current_user'] = {
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin
            }
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, password=password, is_admin=False)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    subjects = Subject.query.all()
    users = User.query.all()
    total_quizzes = sum(len(subject.quizzes) for subject in subjects)
    
    return render_template('admin/dashboard.html', subjects=subjects, users=users, total_quizzes=total_quizzes)

@app.route('/admin/subjects', methods=['GET', 'POST'])
def manage_subjects():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        subject = Subject(name=name, description=description)
        db.session.add(subject)
        db.session.commit()
        flash('Subject added successfully!')
        return redirect(url_for('manage_subjects'))
    
    search_query = request.args.get('search', '')
    if search_query:
        subjects = Subject.query.filter(
            (Subject.name.ilike(f'%{search_query}%')) |
            (Subject.description.ilike(f'%{search_query}%'))
        ).all()
    else:
        subjects = Subject.query.all()
    
    return render_template('admin/subjects.html', subjects=subjects, search_query=search_query)

@app.route('/admin/subjects/<int:subject_id>/edit', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    subject = Subject.query.get_or_404(subject_id)
    if request.method == 'POST':
        subject.name = request.form['name']
        subject.description = request.form['description']
        db.session.commit()
        flash('Subject updated successfully!')
        return redirect(url_for('manage_subjects'))
    return render_template('admin/edit_subject.html', subject=subject)

@app.route('/admin/subjects/<int:subject_id>/delete')
def delete_subject(subject_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted successfully!')
    return redirect(url_for('manage_subjects'))

@app.route('/admin/manage_quizzes', methods=['GET', 'POST'])
def manage_quizzes():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        subject_id = request.form.get('subject_id')
        duration = request.form.get('duration')
        
        if not all([title, subject_id, duration]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('manage_quizzes'))
        
        quiz = Quiz(
            title=title,
            description=description,
            subject_id=subject_id,
            duration=duration
        )
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
        return redirect(url_for('manage_quizzes'))
    
    subjects = Subject.query.all()
    quizzes = Quiz.query.all()
    return render_template('admin/manage_quizzes.html', subjects=subjects, quizzes=quizzes)

@app.route('/admin/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == 'POST':
        quiz.title = request.form.get('title')
        quiz.description = request.form.get('description')
        quiz.subject_id = request.form.get('subject_id')
        quiz.duration = request.form.get('duration')
        
        if not all([quiz.title, quiz.subject_id, quiz.duration]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('edit_quiz', quiz_id=quiz_id))
        
        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('manage_quizzes'))
    
    subjects = Subject.query.all()
    return render_template('admin/edit_quiz.html', quiz=quiz, subjects=subjects)

@app.route('/admin/quizzes/<int:quiz_id>/delete')
def delete_quiz(quiz_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully!')
    return redirect(url_for('manage_quizzes'))

@app.route('/admin/quizzes/<int:quiz_id>/add_question', methods=['GET', 'POST'])
def add_question(quiz_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    if request.method == 'POST':
        try:
            question = Question(
                quiz_id=quiz_id,
                question_text=request.form['question_text'],
                option_a=request.form['option_a'],
                option_b=request.form['option_b'],
                option_c=request.form['option_c'],
                option_d=request.form['option_d'],
                correct_option=request.form['correct_option']
            )
            db.session.add(question)
            db.session.commit()
            flash('Question added successfully!', 'success')
            return redirect(url_for('edit_quiz', quiz_id=quiz_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding question: {str(e)}', 'error')
            return redirect(url_for('add_question', quiz_id=quiz_id))
    
    return render_template('admin/add_question.html', quiz=quiz)

@app.route('/admin/questions/<int:question_id>/edit', methods=['GET', 'POST'])
def edit_question(question_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    question = Question.query.get_or_404(question_id)
    if request.method == 'POST':
        question.question_text = request.form['question_text']
        question.option_a = request.form['option_a']
        question.option_b = request.form['option_b']
        question.option_c = request.form['option_c']
        question.option_d = request.form['option_d']
        question.correct_option = request.form['correct_option']
        db.session.commit()
        flash('Question updated successfully!')
        return redirect(url_for('edit_quiz', quiz_id=question.quiz_id))
    return render_template('admin/edit_question.html', question=question)

@app.route('/admin/questions/<int:question_id>/delete')
def delete_question(question_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!')
    return redirect(url_for('manage_questions', quiz_id=quiz_id))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    search_query = request.args.get('search', '')
    current_time = datetime.utcnow()
    
    if search_query:
        subjects = Subject.query.filter(
            (Subject.name.ilike(f'%{search_query}%')) |
            (Subject.description.ilike(f'%{search_query}%'))
        ).all()
        available_quizzes = Quiz.query.filter(
            (Quiz.title.ilike(f'%{search_query}%')) |
            (Quiz.description.ilike(f'%{search_query}%'))
        ).all()
    else:
        subjects = Subject.query.all()
        available_quizzes = Quiz.query.all()
    
    attempts = QuizAttempt.query.filter_by(user_id=session['user_id']).all()
    return render_template('user/dashboard.html', 
                         subjects=subjects, 
                         attempts=attempts, 
                         available_quizzes=available_quizzes,
                         search_query=search_query,
                         now=current_time)

@app.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
def take_quiz(quiz_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if request.method == 'POST':
        score = 0
        total_questions = len(questions)
        
        for question in questions:
            answer = request.form.get(f'question_{question.id}')
            if answer == question.correct_option:
                score += 1
        
        final_score = (score / total_questions) * 100 if total_questions > 0 else 0
        attempt = QuizAttempt(user_id=session['user_id'], quiz_id=quiz_id, score=final_score)
        db.session.add(attempt)
        db.session.commit()
        
        flash(f'Quiz completed! Your score: {final_score:.1f}%')
        return redirect(url_for('quiz_result', attempt_id=attempt.id))
    
    return render_template('user/attempt_quiz.html', quiz=quiz, questions=questions)

@app.route('/quiz/result/<int:attempt_id>')
def quiz_result(attempt_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    if attempt.user_id != session['user_id']:
        flash('You can only view your own quiz results.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('user/quiz_result.html', attempt=attempt)

@app.route('/admin/visualize')
def visualize_admin():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    quizzes = Quiz.query.all()
    quiz_data = []
    for quiz in quizzes:
        attempts = QuizAttempt.query.filter_by(quiz_id=quiz.id).all()
        if attempts:
            avg_score = sum(attempt.score for attempt in attempts) / len(attempts)
            quiz_data.append({
                'name': quiz.title,
                'value': round(avg_score, 1)
            })
    
    return render_template('admin/visualize.html', quiz_data=quiz_data)

@app.route('/visualize_user_summary')
def visualize_user_summary():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    attempts = QuizAttempt.query.filter_by(user_id=session['user_id']).all()
    subject_data = {}
    
    for attempt in attempts:
        subject_name = attempt.quiz.subject.name
        if subject_name not in subject_data:
            subject_data[subject_name] = []
        subject_data[subject_name].append(attempt.score)
    
    subject_averages = []
    for subject, scores in subject_data.items():
        avg_score = sum(scores) / len(scores)
        subject_averages.append({
            'name': subject,
            'value': round(avg_score, 1)
        })
    
    return render_template('user/visualize.html', subject_data=subject_averages)

@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            is_admin = request.form.get('is_admin') == 'on'
            
            if not username or not password:
                flash('Username and password are required.', 'error')
                return redirect(url_for('manage_users'))
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return redirect(url_for('manage_users'))
            
            new_user = User(
                username=username,
                password=password,
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('manage_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user: {str(e)}', 'error')
            return redirect(url_for('manage_users'))
    
    search_query = request.args.get('search', '')
    if search_query:
        users = User.query.filter(
            (User.username.ilike(f'%{search_query}%')) &
            (User.is_admin == False)
        ).all()
    else:
        users = User.query.filter_by(is_admin=False).all()
    
    return render_template('admin/users.html', users=users, search_query=search_query)

@app.route('/admin/users/<int:user_id>/scores')
def view_user_scores(user_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    attempts = QuizAttempt.query.filter_by(user_id=user_id).all()
    return render_template('admin/user_scores.html', user=user, attempts=attempts)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('Cannot delete admin users.', 'error')
        return redirect(url_for('manage_users'))
    
    QuizAttempt.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    
    flash('User and all their quiz attempts have been deleted successfully!')
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            is_admin = request.form.get('is_admin') == 'on'
            
            if not username:
                flash('Username is required.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            existing_user = User.query.filter(User.username == username, User.id != user_id).first()
            if existing_user:
                flash('Username already exists.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            user.username = username
            if password:
                user.password = password
            user.is_admin = is_admin
            
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('manage_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/add', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('You need admin privileges to access this page.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            is_admin = request.form.get('is_admin') == 'on'
            
            if not username or not password:
                flash('Username and password are required.', 'error')
                return redirect(url_for('add_user'))
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return redirect(url_for('add_user'))
            
            new_user = User(
                username=username,
                password=password,
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('manage_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user: {str(e)}', 'error')
            return redirect(url_for('add_user'))
    
    return render_template('admin/add_user.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(debug=True)
