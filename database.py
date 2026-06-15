from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ---------------- USER MODEL ---------------- #

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    # Relationship
    predictions = db.relationship(
        'PredictionHistory',
        backref='user',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    def set_password(self, password):
        """Hash and set the password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the password matches"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


# ---------------- PREDICTION MODEL ---------------- #

class PredictionHistory(db.Model):
    __tablename__ = "prediction_history"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Foreign Key (linked to user)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Instagram Profile Data
    username = db.Column(db.String(100), nullable=False, index=True)
    full_name = db.Column(db.String(200), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    
    # Feature Columns
    profile_pic = db.Column(db.Integer, default=0)  # 0 or 1
    username_digit_ratio = db.Column(db.Float, default=0.0)
    fullname_words = db.Column(db.Integer, default=0)
    fullname_digit_ratio = db.Column(db.Float, default=0.0)
    name_equals_username = db.Column(db.Integer, default=0)  # 0 or 1
    description_length = db.Column(db.Integer, default=0)
    external_url = db.Column(db.Integer, default=0)  # 0 or 1
    is_private = db.Column(db.Integer, default=0)  # 0 or 1
    posts = db.Column(db.Integer, default=0)
    followers = db.Column(db.Integer, default=0)
    follows = db.Column(db.Integer, default=0)
    
    # Additional features for better prediction
    followers_following_ratio = db.Column(db.Float, default=0.0)
    engagement_rate = db.Column(db.Float, default=0.0)
    posts_per_day = db.Column(db.Float, default=0.0)
    
    # Prediction Results
    prediction = db.Column(db.String(20), nullable=False)  # 'Real' or 'Fake'
    confidence = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)  # 'Low', 'Medium', 'High', 'Critical'
    
    # Additional Analysis
    red_flags = db.Column(db.Text, nullable=True)  # Store as JSON string
    green_flags = db.Column(db.Text, nullable=True)  # Store as JSON string
    recommendations = db.Column(db.Text, nullable=True)  # Store as JSON string
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Prediction {self.username} - {self.prediction}>"
    
    def get_red_flags(self):
        """Get red flags as list"""
        return json.loads(self.red_flags) if self.red_flags else []
    
    def set_red_flags(self, flags_list):
        """Set red flags from list"""
        self.red_flags = json.dumps(flags_list)
    
    def get_green_flags(self):
        """Get green flags as list"""
        return json.loads(self.green_flags) if self.green_flags else []
    
    def set_green_flags(self, flags_list):
        """Set green flags from list"""
        self.green_flags = json.dumps(flags_list)
    
    def get_recommendations(self):
        """Get recommendations as list"""
        return json.loads(self.recommendations) if self.recommendations else []
    
    def set_recommendations(self, rec_list):
        """Set recommendations from list"""
        self.recommendations = json.dumps(rec_list)
    
    def to_dict(self):
        """Convert prediction to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'bio': self.bio,
            'prediction': self.prediction,
            'confidence': self.confidence,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'followers': self.followers,
            'follows': self.follows,
            'posts': self.posts,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'red_flags': self.get_red_flags(),
            'green_flags': self.get_green_flags(),
            'recommendations': self.get_recommendations()
        }


# ---------------- SESSION MODEL (Optional for tracking) ---------------- #

class UserSession(db.Model):
    __tablename__ = "user_sessions"
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f"<UserSession {self.user_id} - {self.session_token[:10]}>"


# ---------------- API LOGS (Optional for monitoring) ---------------- #

class APILog(db.Model):
    __tablename__ = "api_logs"
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    endpoint = db.Column(db.String(100), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    status_code = db.Column(db.Integer, nullable=False)
    response_time = db.Column(db.Float, nullable=True)  # in milliseconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<APILog {self.endpoint} - {self.status_code}>"