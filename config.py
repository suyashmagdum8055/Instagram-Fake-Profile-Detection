import os

class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "instagram-detector-secret-key"
    )

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instagram_detector.db')}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MODEL_PATH = "models/fake_account_model.pkl"

    FAKE_THRESHOLD = 0.5