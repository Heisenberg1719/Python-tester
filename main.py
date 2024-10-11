import os
from flask import *
from flask_cors import CORS
from jwt.exceptions import *
from datetime import timedelta
from flask_jwt_extended import *
from datetime import datetime, timezone
from flask_jwt_extended.exceptions import *
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))  # Secret key for Flask session
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", os.urandom(24))  # Secret key for JWT
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']  # Store JWT in cookies and headers
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)  # Access token expiration time
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(hours=3)  # Refresh token expiration time
app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # CSRF protection for JWT cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Set secure flag for cookies in production
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Session timeout after 15 minutes of inactivity

jwt = JWTManager(app)

# User store simulation (in-memory) with hashed passwords
users_db = {
    'user1@example.com': {'password': generate_password_hash('password123')},
    'user2@example.com': {'password': generate_password_hash('password456')},
    'admin@example.com': {'password': generate_password_hash('adminpass')}
}

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)
    session.modified = True  # Reset session timeout on each request

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    # Check if the user exists and the password is correct
    if email not in users_db or not check_password_hash(users_db[email]['password'], password):
        return jsonify({'message': 'Invalid email or password.'}), 401

    # Clear any existing tokens from the session, create new tokens, and return them in cookies
    session['logged_in'] = True
    session['user'] = email
    response = jsonify(message='Login successful.')
    response.set_cookie('access_token', create_access_token(identity=email, expires_delta=timedelta(minutes=10)), httponly=True, samesite='Strict', secure=True)
    response.set_cookie('refresh_token', create_refresh_token(identity=email, expires_delta=timedelta(hours=3)), httponly=True, samesite='Strict', secure=True)
    return response, 200


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity, expires_delta=timedelta(minutes=10))

        response = jsonify({'message': 'Token refreshed.'})
        response.set_cookie('access_token', access_token, httponly=True, samesite='Strict', secure=True)

        return response
    except ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired.'}), 401
    except RevokedTokenError:
        return jsonify({'message': 'Token has been revoked.'}), 401
    except FreshTokenRequired:
        return jsonify({'message': 'A fresh token is required.'}), 401
    except WrongTokenError:
        return jsonify({'message': 'Wrong token type.'}), 401
    except NoAuthorizationError:
        return jsonify({'message': 'Authorization token is missing.'}), 401
    except JWTDecodeError:
        return jsonify({'message': 'Token is malformed or invalid.'}), 401
    except InvalidTokenError:
        return jsonify({'message': 'Token is invalid.'}), 401
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    identity = get_jwt_identity()

    # Clear session and cookies
    session.clear()
    response = jsonify({'message': 'Logout successful.'})
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')

    return response

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    identity = get_jwt_identity()
    if not session.get('logged_in'):
        return jsonify({'message': 'Session expired, please log in again.'}), 401
    return jsonify({'message': f'Welcome {identity}! This is a protected route.'})

@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': f'eeew to home.'})

if __name__ == '__main__':
    # Use Waitress for production-level serving
    from waitress import serve
    serve(app, host='0.0.0.0', port=5000)
