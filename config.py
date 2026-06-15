import os

class Config:
    SECRET_KEY = 'your-secret-key-here-change-in-production'
    
    # MySQL Database Configuration
    # Update these values with your MySQL credentials
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = '3366'
    MYSQL_DB = 'instagram_detector'
    MYSQL_PORT = 3306
    
    # SQLAlchemy Database URI for MySQL
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }
    
    # Model settings
    MODEL_PATH = 'models/fake_account_model.pkl'
    
    # Threshold for classification
    FAKE_THRESHOLD = 0.5