# app.py - Main Flask Application
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore, storage
import os
import json
from datetime import datetime
import stripe
import openai
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Enable CORS for frontend integration
CORS(app, origins=['*'])

# Configure Stripe (use environment variables in production)
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Configure OpenAI for AI support
openai.api_key = os.environ.get('OPENAI_API_KEY')

# Initialize Firebase Admin SDK
def initialize_firebase():
    try:
        # In production, use service account key from environment
        if not firebase_admin._apps:
            # For development - replace with your Firebase config
            firebase_config = {
                "type": "service_account",
                "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
                "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
                "private_key": os.environ.get('FIREBASE_PRIVATE_KEY', '').replace('\\n', '\n'),
                "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
                "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
            
            cred = credentials.Certificate(firebase_config)
            firebase_admin.initialize_app(cred, {
                'storageBucket': os.environ.get('FIREBASE_STORAGE_BUCKET')
            })
        
        print("✅ Firebase initialized successfully")
    except Exception as e:
        print(f"❌ Firebase initialization error: {e}")

initialize_firebase()

# Get Firestore database instance
db = firestore.client()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verify Firebase ID token
        id_token = request.headers.get('Authorization')
        if not id_token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if id_token.startswith('Bearer '):
                id_token = id_token[7:]
            
            decoded_token = auth.verify_id_token(id_token)
            request.user = decoded_token
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated_function

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        id_token = request.headers.get('Authorization')
        if not id_token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            if id_token.startswith('Bearer '):
                id_token = id_token[7:]
            
            decoded_token = auth.verify_id_token(id_token)
            user_id = decoded_token['uid']
            
            # Check if user is admin
            user_doc = db.collection('users').document(user_id).get()
            if not user_doc.exists or not user_doc.to_dict().get('is_admin', False):
                return jsonify({'error': 'Admin access required'}), 403
            
            request.user = decoded_token
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Invalid token or insufficient permissions'}), 401
    
    return decorated_function

# Routes

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

# Authentication Routes

@app.route('/api/auth/verify', methods=['POST'])
def verify_token():
    """Verify Firebase ID token and return user info"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        
        decoded_token = auth.verify_id_token(id_token)
        user_id = decoded_token['uid']
        
        # Get or create user profile in Firestore
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            # Create new user profile
            user_data = {
                'uid': user_id,
                'email': decoded_token.get('email'),
                'name': decoded_token.get('name', ''),
                'is_premium': False,
                'is_admin': False,
                'created_at': datetime.utcnow(),
                'games_played': [],
                'subscription_status': 'free'
            }
            user_ref.set(user_data)
        else:
            user_data = user_doc.to_dict()
        
        return jsonify({
            'success': True,
            'user': user_data
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Games Routes

@app.route('/api/games', methods=['GET'])
def get_games():
    """Get all games with optional filtering"""
    try:
        games_ref = db.collection('games')
        
        # Filter by category if provided
        category = request.args.get('category')
        if category:
            games_ref = games_ref.where('category', '==', category)
        
        # Filter by platform if provided
        platform = request.args.get('platform')
        if platform:
            games_ref = games_ref.where('platforms', 'array_contains', platform)
        
        games = []
        for doc in games_ref.stream():
            game_data = doc.to_dict()
            game_data['id'] = doc.id
            games.append(game_data)
        
        return jsonify({'games': games})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/games/<game_id>', methods=['GET'])
def get_game(game_id):
    """Get specific game details"""
    try:
        game_doc = db.collection('games').document(game_id).get()
        if not game_doc.exists:
            return jsonify({'error': 'Game not found'}), 404
        
        game_data = game_doc.to_dict()
        game_data['id'] = game_doc.id
        
        return jsonify({'game': game_data})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/games', methods=['POST'])
@admin_required
def add_game():
    """Add new game (Admin only)"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'description', 'category', 'platforms']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        game_data = {
            'title': data['title'],
            'description': data['description'],
            'category': data['category'],
            'platforms': data['platforms'],
            'tags': data.get('tags', []),
            'is_premium': data.get('is_premium', False),
            'rating': data.get('rating', 0),
            'image_url': data.get('image_url', ''),
            'created_at': datetime.utcnow(),
            'created_by': request.user['uid'],
            'status': 'pending_approval'
        }
        
        # Add game to Firestore
        game_ref = db.collection('games').add(game_data)
        
        return jsonify({
            'success': True,
            'game_id': game_ref[1].id,
            'message': 'Game added successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Premium Routes

@app.route('/api/premium/upgrade', methods=['POST'])
@login_required
def upgrade_premium():
    """Handle premium upgrade with Stripe"""
    try:
        data = request.get_json()
        user_id = request.user['uid']
        
        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': 999,  # $9.99 in cents
                    'product_data': {
                        'name': 'GameVerse Premium Membership',
                        'description': 'Monthly premium gaming subscription'
                    },
                    'recurring': {
                        'interval': 'month'
                    }
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{request.host_url}premium/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{request.host_url}premium/cancel",
            client_reference_id=user_id
        )
        
        return jsonify({
            'success': True,
            'checkout_url': checkout_session.url
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/premium/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks for payment confirmation"""
    try:
        payload = request.get_data()
        sig_header = request.headers.get('Stripe-Signature')
        endpoint_secret = os.environ.get('STRIPE_ENDPOINT_SECRET')
        
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            user_id = session['client_reference_id']
            
            # Update user to premium status
            user_ref = db.collection('users').document(user_id)
            user_ref.update({
                'is_premium': True,
                'subscription_status': 'active',
                'upgraded_at': datetime.utcnow()
            })
            
            print(f"✅ User {user_id} upgraded to premium")
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        return jsonify({'error': str(e)}), 400

# Admin Routes

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    """Get all users (Admin only)"""
    try:
        users = []
        for doc in db.collection('users').stream():
            user_data = doc.to_dict()
            user_data['id'] = doc.id
            users.append(user_data)
        
        return jsonify({'users': users})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<user_id>/premium', methods=['POST'])
@admin_required
def grant_premium(user_id):
    """Grant premium status to user (Admin only)"""
    try:
        user_ref = db.collection('users').document(user_id)
        user_ref.update({
            'is_premium': True,
            'subscription_status': 'admin_granted',
            'upgraded_at': datetime.utcnow()
        })
        
        return jsonify({
            'success': True,
            'message': 'Premium status granted'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/games/approve/<game_id>', methods=['POST'])
@admin_required
def approve_game(game_id):
    """Approve pending game (Admin only)"""
    try:
        game_ref = db.collection('games').document(game_id)
        game_ref.update({
            'status': 'approved',
            'approved_at': datetime.utcnow(),
            'approved_by': request.user['uid']
        })
        
        return jsonify({
            'success': True,
            'message': 'Game approved successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# AI Support Routes

@app.route('/api/support/chat', methods=['POST'])
@login_required
def ai_chat():
    """AI-powered chat support"""
    try:
        data = request.get_json()
        user_message = data.get('message')
        user_id = request.user['uid']
        
        # Create chat completion with OpenAI
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": """You are a helpful gaming support assistant for GameVerse. 
                    Help users with game-related questions, account issues, and general support.
                    Be friendly, helpful, and gaming-focused in your responses."""
                },
                {"role": "user", "content": user_message}
            ],
            max_tokens=150,
            temperature=0.7
        )
        
        ai_response = response.choices[0].message.content
        
        # Store conversation in Firestore
        db.collection('support_chats').add({
            'user_id': user_id,
            'user_message': user_message,
            'ai_response': ai_response,
            'timestamp': datetime.utcnow()
        })
        
        return jsonify({
            'success': True,
            'response': ai_response
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/support/ticket', methods=['POST'])
@login_required
def create_ticket():
    """Create support ticket"""
    try:
        data = request.get_json()
        user_id = request.user['uid']
        
        ticket_data = {
            'user_id': user_id,
            'subject': data.get('subject'),
            'message': data.get('message'),
            'priority': data.get('priority', 'medium'),
            'status': 'open',
            'created_at': datetime.utcnow()
        }
        
        ticket_ref = db.collection('support_tickets').add(ticket_data)
        
        return jsonify({
            'success': True,
            'ticket_id': ticket_ref[1].id,
            'message': 'Support ticket created successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Analytics Routes

@app.route('/api/analytics/stats', methods=['GET'])
@admin_required
def get_analytics():
    """Get platform analytics (Admin only)"""
    try:
        # Get user stats
        users_ref = db.collection('users')
        total_users = len(list(users_ref.stream()))
        premium_users = len(list(users_ref.where('is_premium', '==', True).stream()))
        
        # Get game stats
        games_ref = db.collection('games')
        total_games = len(list(games_ref.stream()))
        premium_games = len(list(games_ref.where('is_premium', '==', True).stream()))
        
        # Get ticket stats
        tickets_ref = db.collection('support_tickets')
        open_tickets = len(list(tickets_ref.where('status', '==', 'open').stream()))
        
        stats = {
            'total_users': total_users,
            'premium_users': premium_users,
            'total_games': total_games,
            'premium_games': premium_games,
            'open_tickets': open_tickets,
            'conversion_rate': (premium_users / total_users * 100) if total_users > 0 else 0
        }
        
        return jsonify({'stats': stats})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check route
@app.route('/health')
def health_check():
    """Health check for deployment"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    print("🚀 Starting GameVerse Flask Backend...")
    print(f"📊 Running on port: {port}")
    print(f"🔧 Debug mode: {debug_mode}")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
