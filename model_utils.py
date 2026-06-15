import pickle
import numpy as np
import pandas as pd
import os
import json

class InstagramDetector:
    def __init__(self, model_path='models/fake_account_model.pkl'):
        self.model = None
        self.model_path = model_path
        self.feature_names = [
            'profile pic',
            'nums/length username',
            'fullname words',
            'nums/length fullname',
            'name==username',
            'description length',
            'external URL',
            'private',
            '#posts',
            '#followers',
            '#follows'
        ]
        self.load_model()
    
    def load_model(self):
        """Load the trained XGBoost model"""
        try:
            # Check multiple possible paths
            possible_paths = [
                self.model_path,
                'model/fake_model.pkl',
                'model/fake_account_model.pkl',
                '../models/fake_account_model.pkl',
                os.path.join(os.path.dirname(__file__), self.model_path),
                os.path.join(os.path.dirname(__file__), 'models/fake_account_model.pkl')
            ]
            
            model_loaded = False
            for path in possible_paths:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        self.model = pickle.load(f)
                    print(f"Model loaded successfully from {path}")
                    model_loaded = True
                    break
            
            if model_loaded:
                print(f"Model type: {type(self.model)}")
                print(f"Number of features expected: {len(self.feature_names)}")
                return True
            else:
                print(f"Model file not found at any expected location")
                print(f"Checked paths:")
                for path in possible_paths:
                    print(f"  - {path}")
                print(f"Current working directory: {os.getcwd()}")
                return False
                
        except Exception as e:
            print(f"Error loading model: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def calculate_digit_ratio(self, text):
        """Calculate ratio of digits to total characters"""
        if not text or len(text) == 0:
            return 0.0
        digit_count = sum(c.isdigit() for c in str(text))
        return digit_count / len(str(text))
    
    def prepare_features(self, profile_data):
        """
        Extract and prepare features from profile data for the model
        """
        username = profile_data.get('username', '')
        full_name = profile_data.get('full_name', '')
        bio = profile_data.get('bio', '')
        
        # Calculate all features
        features = {
            'profile pic': 1 if profile_data.get('has_profile_pic', False) else 0,
            'nums/length username': self.calculate_digit_ratio(username),
            'fullname words': len(str(full_name).split()),
            'nums/length fullname': self.calculate_digit_ratio(full_name),
            'name==username': 1 if str(full_name).lower() == str(username).lower() else 0,
            'description length': len(str(bio)),
            'external URL': 1 if profile_data.get('external_url', False) else 0,
            'private': 1 if profile_data.get('is_private', False) else 0,
            '#posts': profile_data.get('posts', 0),
            '#followers': profile_data.get('followers', 0),
            '#follows': profile_data.get('following', 0)
        }
        
        # Convert to numpy array in the correct order
        feature_values = [features[name] for name in self.feature_names]
        
        print("Features prepared:")
        for name, value in zip(self.feature_names, feature_values):
            if isinstance(value, float):
                print(f"  {name}: {value:.4f}")
            else:
                print(f"  {name}: {value}")
        
        return np.array(feature_values, dtype=np.float32).reshape(1, -1)
    
    def predict(self, profile_data):
        """
        Predict if the Instagram profile is fake or real
        """
        if self.model is None:
            return {
                'prediction': 'Error',
                'confidence': 0,
                'is_fake': False,
                'error': 'Model not loaded. Please ensure model file exists in models/ directory.'
            }
        
        try:
            # Prepare features
            features = self.prepare_features(profile_data)
            print(f"Feature array shape: {features.shape}")
            
            # Make prediction
            prediction = self.model.predict(features)[0]
            print(f"Raw prediction: {prediction} (0=Real, 1=Fake)")
            
            # Get probability/confidence
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(features)[0]
                confidence = max(probabilities)
                class_probs = {
                    'real': float(probabilities[0]),
                    'fake': float(probabilities[1])
                }
                print(f"Probabilities - Real: {probabilities[0]:.3f}, Fake: {probabilities[1]:.3f}")
            else:
                # Fallback for models without predict_proba
                confidence = 0.7 if prediction == 1 else 0.3
                class_probs = {
                    'real': 0.3 if prediction == 1 else 0.7,
                    'fake': 0.7 if prediction == 1 else 0.3
                }
                print("Model doesn't support probability prediction, using fallback")
            
            result = 'Fake' if prediction == 1 else 'Real'
            
            return {
                'prediction': result,
                'confidence': float(confidence),
                'is_fake': bool(prediction == 1),
                'class_probabilities': class_probs,
                'features_used': {name: float(value) if isinstance(value, np.number) else value 
                                 for name, value in zip(self.feature_names, features[0])}
            }
            
        except Exception as e:
            print(f"Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'prediction': 'Error',
                'confidence': 0,
                'is_fake': False,
                'error': str(e)
            }
    
    def analyze_profile(self, profile_data):
        """Provide detailed analysis with red/green flags"""
        prediction_result = self.predict(profile_data)
        
        if prediction_result.get('error'):
            return prediction_result
        
        analysis = {
            **prediction_result,
            'red_flags': [],
            'green_flags': [],
            'recommendations': []
        }
        
        # Analyze for red flags
        if not profile_data.get('has_profile_pic', False):
            analysis['red_flags'].append({
                'type': 'critical',
                'message': 'No profile picture',
                'reason': 'Fake accounts often avoid adding profile pictures'
            })
        
        followers = profile_data.get('followers', 0)
        following = profile_data.get('following', 0)
        
        if followers < 50 and following > 500:
            analysis['red_flags'].append({
                'type': 'high',
                'message': 'Suspicious followers/following ratio',
                'reason': f'Following {following} accounts but only {followers} followers'
            })
        
        # Check follower/following ratio
        if following > 0 and followers / following < 0.1:
            analysis['red_flags'].append({
                'type': 'high',
                'message': 'Very low follower to following ratio',
                'reason': f'Only {followers} followers while following {following} accounts'
            })
        
        bio_length = len(profile_data.get('bio', ''))
        if bio_length < 10:
            analysis['red_flags'].append({
                'type': 'medium',
                'message': 'Very short or no bio',
                'reason': 'Fake accounts typically have minimal or generic bios'
            })
        
        username = profile_data.get('username', '')
        digit_ratio = sum(c.isdigit() for c in username) / len(username) if username else 0
        if digit_ratio > 0.3:
            analysis['red_flags'].append({
                'type': 'medium',
                'message': 'Username contains many numbers',
                'reason': f'{int(digit_ratio * 100)}% of username is numbers'
            })
        
        # Check posts count
        posts = profile_data.get('posts', 0)
        if posts == 0 and followers > 0:
            analysis['red_flags'].append({
                'type': 'medium',
                'message': 'No posts but has followers',
                'reason': 'Suspicious activity pattern'
            })
        
        # Analyze for green flags
        if profile_data.get('has_profile_pic', False):
            analysis['green_flags'].append({
                'type': 'good',
                'message': 'Has profile picture',
                'reason': 'Real accounts typically have profile photos'
            })
        
        if followers > 100:
            analysis['green_flags'].append({
                'type': 'good',
                'message': 'Substantial follower count',
                'reason': f'{followers} followers indicates established account'
            })
        
        if bio_length > 50:
            analysis['green_flags'].append({
                'type': 'good',
                'message': 'Detailed bio',
                'reason': f'{bio_length} characters - shows engagement'
            })
        
        if profile_data.get('external_url', False):
            analysis['green_flags'].append({
                'type': 'good',
                'message': 'Has external link',
                'reason': 'Links to other platforms suggest authenticity'
            })
        
        if posts > 50:
            analysis['green_flags'].append({
                'type': 'good',
                'message': 'Significant post history',
                'reason': f'{posts} posts indicates active account'
            })
        
        # Calculate risk score
        if analysis['prediction'] == 'Fake':
            risk_score = analysis['confidence'] * 100
            # Add extra risk based on red flags
            risk_score += min(len(analysis['red_flags']) * 5, 20)
        else:
            risk_score = (1 - analysis['confidence']) * 100
            # Reduce risk based on green flags
            risk_score = max(0, risk_score - len(analysis['green_flags']) * 3)
        
        # Ensure risk score is within bounds
        risk_score = min(100, max(0, risk_score))
        
        # Add risk level
        if risk_score < 20:
            risk_level = 'Low'
        elif risk_score < 40:
            risk_level = 'Medium'
        elif risk_score < 70:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
        
        analysis['risk_score'] = round(risk_score, 1)
        analysis['risk_level'] = risk_level
        
        # Generate recommendations
        if analysis['prediction'] == 'Fake':
            analysis['recommendations'] = [
                "This profile shows strong signs of being fake or automated",
                "Be extremely cautious when interacting with this account",
                "Do not share personal information or click on links",
                "Consider blocking or reporting this profile",
                "Enable two-factor authentication on your own account"
            ]
        else:
            analysis['recommendations'] = [
                "This profile appears authentic and legitimate",
                "No immediate security concerns detected",
                "Continue normal interactions with caution",
                "Remember to always practice good security habits"
            ]
        
        # Print summary
        print("\n" + "="*50)
        print(f"Analysis Complete - {analysis['prediction']} Profile")
        print(f"Confidence: {analysis['confidence']*100:.1f}%")
        print(f"Risk Score: {analysis['risk_score']}% ({analysis['risk_level']})")
        print(f"Red Flags: {len(analysis['red_flags'])}")
        print(f"Green Flags: {len(analysis['green_flags'])}")
        print("="*50 + "\n")
        
        return analysis

# Create global detector instance
detector = InstagramDetector()