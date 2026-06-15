from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import requests
import json
import os
import sys
import re
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps

from config import Config
from database import db, User, PredictionHistory, UserSession, APILog
from model_utils import detector

app = Flask(__name__)
app.config.from_object(Config)

# Security: Use ProxyFix for proper IP handling behind reverse proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Ensure secret key is set with a strong default
if not app.config.get('SECRET_KEY') or app.config['SECRET_KEY'] == 'your-secret-key-here-change-in-production':
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    print("Warning: Using default SECRET_KEY. Set a secure key in production!")

# Session configuration for security
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)

# Flask-Login configuration
app.config['REMEMBER_COOKIE_SECURE'] = os.environ.get('REMEMBER_COOKIE_SECURE', 'False').lower() == 'true'
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=31)

# Rate limiting configuration
RATE_LIMIT = {
    'login': {'attempts': 5, 'window': 300},  # 5 attempts in 5 minutes
    'predict': {'attempts': 20, 'window': 3600}  # 20 predictions per hour
}
failed_login_attempts = {}

# Initialize extensions
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rate limiting decorator
def rate_limit(limit_type):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if limit_type == 'login' and request.method == 'POST':
                username = request.form.get('username', '')
                key = f"{request.remote_addr}:{username}"
                
                if key in failed_login_attempts:
                    attempts, first_attempt = failed_login_attempts[key]
                    if attempts >= RATE_LIMIT['login']['attempts']:
                        time_passed = (datetime.utcnow() - first_attempt).total_seconds()
                        if time_passed < RATE_LIMIT['login']['window']:
                            remaining = int(RATE_LIMIT['login']['window'] - time_passed)
                            flash(f'Too many login attempts. Please try again in {remaining} seconds.', 'error')
                            return redirect(url_for('login'))
                        else:
                            del failed_login_attempts[key]
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Create tables
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Error creating tables: {e}")
        print("Make sure MySQL is running and credentials are correct")
        sys.exit(1)

# Helper function to log API calls
def log_api_call(endpoint, method, status_code, response_time=None):
    if current_user.is_authenticated:
        try:
            log = APILog(
                user_id=current_user.id,
                endpoint=endpoint,
                method=method,
                ip_address=request.remote_addr,
                status_code=status_code,
                response_time=response_time
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            print(f"Error logging API call: {e}")

# Helper function to sanitize input
def sanitize_input(text):
    if not text:
        return ''
    # Remove potentially dangerous characters
    text = re.sub(r'[<>{}]', '', text)
    # Limit length
    if len(text) > 200:
        text = text[:200]
    return text.strip()

# Helper function to validate username
def validate_username(username):
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 30:
        return False, "Username must be at most 30 characters"
    if not re.match(r'^[a-zA-Z0-9_.]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and dots"
    return True, ""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login')
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        remember = True if request.form.get('remember') else False
        
        # Track failed attempts
        key = f"{request.remote_addr}:{username}"
        
        # Check by username first, then by email
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User.query.filter_by(email=username).first()
        
        if user and user.check_password(password):
            # Clear failed attempts on successful login
            if key in failed_login_attempts:
                del failed_login_attempts[key]
            
            # Clear any existing session
            logout_user()
            
            # Login user
            login_user(user, remember=remember, duration=timedelta(days=31))
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            # Track failed attempt
            if key in failed_login_attempts:
                attempts, first_attempt = failed_login_attempts[key]
                failed_login_attempts[key] = (attempts + 1, first_attempt)
            else:
                failed_login_attempts[key] = (1, datetime.utcnow())
            
            remaining = RATE_LIMIT['login']['attempts'] - failed_login_attempts[key][0]
            if remaining > 0:
                flash(f'Invalid username/email or password. {remaining} attempts remaining.', 'error')
            else:
                flash('Too many failed attempts. Please try again later.', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))
        
        # Validate username
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('signup'))
        
        # Validate email
        if not re.match(r'^[^\s@]+@([^\s@]+\.)+[^\s@]+$', email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))
        
        # Strong password validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('signup'))
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter', 'error')
            return redirect(url_for('signup'))
        
        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter', 'error')
            return redirect(url_for('signup'))
        
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one number', 'error')
            return redirect(url_for('signup'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        
        try:
            # Create new user
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    try:
        # Clear session
        session.clear()
        logout_user()
        flash('Logged out successfully', 'success')
    except Exception as e:
        print(f"Error during logout: {e}")
    
    return redirect(url_for('index'))

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    """Main prediction page - handles both GET and POST requests"""
    if request.method == 'GET':
        return render_template('predict.html')
    
    # Handle POST request - process the prediction
    try:
        # Get form data with derived features
        profile_data = {
            'username': sanitize_input(request.form.get('username', '')).lower(),
            'full_name': sanitize_input(request.form.get('full_name', '')),
            'bio': sanitize_input(request.form.get('bio', '')),
            'has_profile_pic': int(request.form.get('has_profile_pic', 0)),
            'is_private': int(request.form.get('is_private', 0)),
            'external_url': int(request.form.get('external_url', 0)),
            'posts': int(request.form.get('posts', 0)),
            'followers': int(request.form.get('followers', 0)),
            'following': int(request.form.get('following', 0))
        }
        
        # Get derived features from form (sent via hidden inputs)
        derived_features = {
            'followers_following_ratio': float(request.form.get('followers_following_ratio', 0)),
            'engagement_rate': float(request.form.get('engagement_rate', 0)),
            'posts_per_day': float(request.form.get('posts_per_day', 0)),
            'username_digit_ratio': float(request.form.get('username_digit_ratio', 0)),
            'fullname_digit_ratio': float(request.form.get('fullname_digit_ratio', 0)),
            'name_equals_username': int(request.form.get('name_equals_username', 0))
        }
        
        # Validate username
        if not profile_data['username']:
            flash('Please enter an Instagram username', 'error')
            return render_template('predict.html')
        
        is_valid, error_msg = validate_username(profile_data['username'])
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('predict.html')
        
        # Validate number ranges
        if profile_data['followers'] > 10000000:
            flash('Note: Unusually high follower count detected', 'info')
        
        if profile_data['following'] > 10000:
            flash('Note: Very high following count may indicate automated behavior', 'info')
        
        # Combine profile_data and derived_features into a single dictionary
        # This fixes the "takes 2 positional arguments but 3 were given" error
        combined_data = {
            **profile_data,
            **derived_features
        }
        
        # Analyze profile with the XGBoost model - passing only ONE argument
        analysis = detector.analyze_profile(combined_data)
        
        # Check for errors
        if analysis.get('error'):
            flash(f'Error in analysis: {analysis["error"]}', 'error')
            return render_template('predict.html')
        
        # Save to history with all features
        prediction = PredictionHistory(
            user_id=current_user.id,
            username=profile_data['username'],
            full_name=profile_data['full_name'],
            bio=profile_data['bio'],
            profile_pic=profile_data['has_profile_pic'],
            username_digit_ratio=derived_features['username_digit_ratio'],
            fullname_words=len(profile_data['full_name'].split()),
            fullname_digit_ratio=derived_features['fullname_digit_ratio'],
            name_equals_username=derived_features['name_equals_username'],
            description_length=len(profile_data['bio']),
            external_url=profile_data['external_url'],
            is_private=profile_data['is_private'],
            posts=profile_data['posts'],
            followers=profile_data['followers'],
            follows=profile_data['following'],
            followers_following_ratio=derived_features['followers_following_ratio'],
            engagement_rate=derived_features['engagement_rate'],
            posts_per_day=derived_features['posts_per_day'],
            prediction=analysis['prediction'],
            confidence=analysis['confidence'],
            risk_score=analysis.get('risk_score', 0),
            risk_level=analysis.get('risk_level', 'Low')
        )
        
        # Store flags and recommendations as JSON strings
        if hasattr(prediction, 'set_red_flags'):
            prediction.set_red_flags(analysis.get('red_flags', []))
            prediction.set_green_flags(analysis.get('green_flags', []))
            prediction.set_recommendations(analysis.get('recommendations', []))
        
        db.session.add(prediction)
        db.session.commit()
        
        # Format prediction result for result.html
        prediction_result = {
            'id': prediction.id,
            'username': prediction.username,
            'full_name': prediction.full_name,
            'bio': prediction.bio,
            'prediction': prediction.prediction,
            'confidence': round(prediction.confidence * 100, 1),
            'risk_score': prediction.risk_score,
            'risk_level': prediction.risk_level,
            'created_at': prediction.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'followers': prediction.followers,
            'follows': prediction.follows,
            'posts': prediction.posts,
            'is_private': prediction.is_private,
            'has_profile_pic': prediction.profile_pic,
            'external_url': prediction.external_url
        }
        
        # Also prepare analysis with formatted confidence
        analysis['confidence_percentage'] = round(analysis['confidence'] * 100, 1)
        
        return render_template('result.html', 
                             profile_data=profile_data,
                             analysis=analysis,
                             prediction=prediction_result)
    
    except Exception as e:
        db.session.rollback()
        print(f"Prediction error: {e}")
        flash(f'Error analyzing profile: {str(e)}', 'error')
        return render_template('predict.html')

@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    filter_type = request.args.get('filter', 'all')
    search_query = request.args.get('search', '').strip()
    
    # Base query
    query = PredictionHistory.query.filter_by(user_id=current_user.id)
    
    # Apply filters
    if filter_type == 'fake':
        query = query.filter_by(prediction='Fake')
    elif filter_type == 'real':
        query = query.filter_by(prediction='Real')
    
    if search_query:
        query = query.filter(PredictionHistory.username.contains(search_query))
    
    # Get paginated results
    pagination = query.order_by(PredictionHistory.created_at.desc())\
                      .paginate(page=page, per_page=per_page, error_out=False)
    
    # Convert pagination items to serializable format
    searches = []
    for search in pagination.items:
        searches.append({
            'id': search.id,
            'instagram_username': search.username,
            'prediction_result': search.prediction,
            'confidence_score': search.confidence,
            'risk_score': search.risk_score,
            'risk_level': search.risk_level,
            'searched_at': search.created_at,
            'profile_data': {
                'followers': search.followers,
                'follows': search.follows,
                'posts': search.posts
            }
        })
    
    return render_template('history.html', 
                         searches=searches,
                         pagination=pagination,
                         page=page,
                         total_pages=pagination.pages,
                         current_filter=filter_type,
                         search_query=search_query)

@app.route('/api/detect', methods=['POST'])
def api_detect():
    """
    API endpoint for detection without authentication
    """
    start_time = datetime.utcnow()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    # Validate username
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    try:
        # Create profile data from API request
        profile_data = {
            'username': username.lower(),
            'full_name': data.get('full_name', ''),
            'bio': data.get('bio', ''),
            'has_profile_pic': int(data.get('has_profile_pic', 0)),
            'is_private': int(data.get('is_private', 0)),
            'external_url': int(data.get('external_url', 0)),
            'posts': int(data.get('posts', 0)),
            'followers': int(data.get('followers', 0)),
            'following': int(data.get('following', 0))
        }
        
        # Calculate derived features
        derived_features = {
            'followers_following_ratio': calculate_followers_following_ratio(
                profile_data['followers'], profile_data['following']
            ),
            'engagement_rate': calculate_engagement_rate(
                profile_data['posts'], profile_data['followers']
            ),
            'posts_per_day': calculate_posts_per_day(profile_data['posts']),
            'username_digit_ratio': calculate_digit_ratio(profile_data['username']),
            'fullname_digit_ratio': calculate_digit_ratio(profile_data['full_name']),
            'name_equals_username': 1 if profile_data['full_name'].lower() == profile_data['username'].lower() else 0
        }
        
        # Combine data for the detector
        combined_data = {**profile_data, **derived_features}
        analysis = detector.analyze_profile(combined_data)
        
        # Log API call
        response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        if current_user.is_authenticated:
            log_api_call('/api/detect', 'POST', 200, response_time)
        
        return jsonify(analysis)
    
    except Exception as e:
        response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        if current_user.is_authenticated:
            log_api_call('/api/detect', 'POST', 500, response_time)
        return jsonify({'error': str(e)}), 500

# Helper calculation functions for API
def calculate_followers_following_ratio(followers, following):
    if following > 0:
        return followers / following
    return followers if followers > 0 else 0

def calculate_engagement_rate(posts, followers):
    if followers > 0 and posts > 0:
        # Estimated engagement based on typical patterns
        estimated_engagement = min((posts * 50) / followers * 100, 100)
        return round(estimated_engagement, 4)
    return 0

def calculate_posts_per_day(posts):
    # Assume account age estimation based on post count
    if posts >= 1000:
        return 0.5
    elif posts >= 500:
        return 0.3
    elif posts >= 100:
        return 0.2
    elif posts >= 10:
        return 0.1
    return 0.05

def calculate_digit_ratio(text):
    if not text or len(text) == 0:
        return 0
    digit_count = sum(1 for c in text if c.isdigit())
    return digit_count / len(text)

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    """API endpoint to get user's prediction history"""
    limit = request.args.get('limit', 10, type=int)
    limit = min(limit, 50)  # Cap at 50
    
    predictions = PredictionHistory.query.filter_by(user_id=current_user.id)\
                                        .order_by(PredictionHistory.created_at.desc())\
                                        .limit(limit)\
                                        .all()
    
    history_data = []
    for pred in predictions:
        history_data.append({
            'id': pred.id,
            'username': pred.username,
            'prediction': pred.prediction,
            'confidence': pred.confidence,
            'risk_score': pred.risk_score,
            'risk_level': pred.risk_level,
            'searched_at': pred.created_at.isoformat(),
            'followers': pred.followers,
            'follows': pred.follows,
            'posts': pred.posts
        })
    
    return jsonify(history_data)

@app.route('/api/history/<int:prediction_id>', methods=['GET', 'DELETE'])
@login_required
def api_history_detail(prediction_id):
    """API endpoint to get or delete a specific prediction"""
    prediction = PredictionHistory.query.get_or_404(prediction_id)
    
    # Check if the prediction belongs to the current user
    if prediction.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'DELETE':
        try:
            db.session.delete(prediction)
            db.session.commit()
            return jsonify({'message': 'Prediction deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    # GET request - return prediction details
    return jsonify({
        'id': prediction.id,
        'username': prediction.username,
        'full_name': prediction.full_name,
        'bio': prediction.bio,
        'prediction': prediction.prediction,
        'confidence': prediction.confidence,
        'risk_score': prediction.risk_score,
        'risk_level': prediction.risk_level,
        'followers': prediction.followers,
        'follows': prediction.follows,
        'posts': prediction.posts,
        'is_private': prediction.is_private,
        'profile_pic': prediction.profile_pic,
        'external_url': prediction.external_url,
        'searched_at': prediction.created_at.isoformat(),
        'red_flags': prediction.get_red_flags() if hasattr(prediction, 'get_red_flags') else [],
        'green_flags': prediction.get_green_flags() if hasattr(prediction, 'get_green_flags') else []
    })

@app.route('/api/history/all')
@login_required
def api_history_all():
    """API endpoint to get all user history for the history page"""
    predictions = PredictionHistory.query.filter_by(user_id=current_user.id)\
        .order_by(PredictionHistory.created_at.desc())\
        .all()
    
    history_data = []
    for p in predictions:
        history_data.append({
            'id': p.id,
            'username': p.username,
            'prediction': p.prediction,
            'confidence': p.confidence,
            'risk_score': p.risk_score,
            'risk_level': p.risk_level,
            'searched_at': p.created_at.isoformat(),
            'followers': p.followers,
            'follows': p.follows,
            'posts': p.posts
        })
    
    return jsonify(history_data)

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with statistics"""
    total_predictions = PredictionHistory.query.filter_by(user_id=current_user.id).count()
    fake_count = PredictionHistory.query.filter_by(user_id=current_user.id, prediction='Fake').count()
    real_count = PredictionHistory.query.filter_by(user_id=current_user.id, prediction='Real').count()
    
    recent_predictions = PredictionHistory.query.filter_by(user_id=current_user.id)\
                                                .order_by(PredictionHistory.created_at.desc())\
                                                .limit(5)\
                                                .all()
    
    stats = {
        'total': total_predictions,
        'fake': fake_count,
        'real': real_count,
        'fake_percentage': (fake_count / total_predictions * 100) if total_predictions > 0 else 0,
        'recent': recent_predictions
    }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    """API endpoint for dashboard statistics"""
    user_id = current_user.id
    
    total_searches = PredictionHistory.query.filter_by(user_id=user_id).count()
    fake_count = PredictionHistory.query.filter_by(user_id=user_id, prediction='Fake').count()
    real_count = PredictionHistory.query.filter_by(user_id=user_id, prediction='Real').count()
    
    # Calculate risk score based on history
    risk_score = 0
    if total_searches > 0:
        risk_score = (fake_count / total_searches) * 100
    
    # Get last 7 days data for chart
    from datetime import datetime, timedelta
    dates = []
    totals = []
    fake_totals = []
    
    for i in range(6, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        date_start = datetime.combine(date, datetime.min.time())
        date_end = datetime.combine(date, datetime.max.time())
        
        day_total = PredictionHistory.query.filter(
            PredictionHistory.user_id == user_id,
            PredictionHistory.created_at >= date_start,
            PredictionHistory.created_at <= date_end
        ).count()
        
        day_fake = PredictionHistory.query.filter(
            PredictionHistory.user_id == user_id,
            PredictionHistory.prediction == 'Fake',
            PredictionHistory.created_at >= date_start,
            PredictionHistory.created_at <= date_end
        ).count()
        
        dates.append(date.strftime('%a'))
        totals.append(day_total)
        fake_totals.append(day_fake)
    
    # Calculate percentages for pie chart
    real_percent = (real_count / total_searches * 100) if total_searches > 0 else 0
    fake_percent = (fake_count / total_searches * 100) if total_searches > 0 else 0
    
    return jsonify({
        'total_searches': total_searches,
        'fake_count': fake_count,
        'real_count': real_count,
        'risk_score': round(risk_score, 1),
        'total_trend': 0,
        'chart_data': {
            'days': dates,
            'totals': totals,
            'fake': fake_totals,
            'real_percent': round(real_percent, 1),
            'fake_percent': round(fake_percent, 1)
        }
    })

@app.route('/api/dashboard/recent')
@login_required
def api_dashboard_recent():
    """API endpoint for recent activity"""
    user_id = current_user.id
    
    recent_searches = PredictionHistory.query.filter_by(user_id=user_id)\
        .order_by(PredictionHistory.created_at.desc())\
        .limit(5)\
        .all()
    
    activities = []
    for search in recent_searches:
        # Calculate time ago
        time_diff = datetime.utcnow() - search.created_at
        if time_diff.days > 0:
            if time_diff.days == 1:
                time_ago = "Yesterday"
            else:
                time_ago = f"{time_diff.days} days ago"
        elif time_diff.seconds > 3600:
            hours = time_diff.seconds // 3600
            time_ago = f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif time_diff.seconds > 60:
            minutes = time_diff.seconds // 60
            time_ago = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            time_ago = "Just now"
        
        activities.append({
            'username': search.username,
            'prediction': search.prediction,
            'risk_score': round(search.risk_score, 1),
            'risk_level': search.risk_level,
            'time_ago': time_ago,
            'created_at': search.created_at.isoformat()
        })
    
    return jsonify(activities)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

if __name__ == '__main__':
    
    print("Starting Instagram Fake Profile Detector...")
    
    print("XGBoost Model loaded and ready for predictions")
    print("Access the app at: http://localhost:5000")
    print("Use /predict to analyze profiles")
    
    
    # Get port from environment variable for production
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    app.run(debug=debug, host='0.0.0.0', port=port)