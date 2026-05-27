import logging
from datetime import timedelta
from typing import Tuple

import bcrypt
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)

from database import Database

logger = logging.getLogger('threatiq')
auth_bp = Blueprint('auth', __name__)
db = Database()

# ── Constants ──────────────────────────────────────────────────
MIN_PASSWORD_LEN = 8
MAX_EMAIL_LEN    = 254
ACCESS_EXPIRES   = timedelta(hours=24)
REFRESH_EXPIRES  = timedelta(days=30)
MAX_ATTEMPTS     = 5


# ══════════════════════════════════════════════════════════════
# PASSWORD UTILITIES
# ══════════════════════════════════════════════════════════════

def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def validate_email(email: str) -> Tuple[bool, str]:
    if not email or len(email) > MAX_EMAIL_LEN:
        return False, 'Invalid email length'
    parts = email.split('@')
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False, 'Invalid email format'
    if '.' not in parts[1]:
        return False, 'Invalid email domain'
    return True, ''


def validate_password(password: str) -> Tuple[bool, str]:
    if not password or len(password) < MIN_PASSWORD_LEN:
        return False, f'Password must be at least {MIN_PASSWORD_LEN} characters'
    if not any(c.isupper() for c in password):
        return False, 'Password must contain at least one uppercase letter'
    if not any(c.isdigit() for c in password):
        return False, 'Password must contain at least one number'
    return True, ''


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # FIX: accept username from register modal (login.html sends regUsername)
        username = data.get('username', '').strip()
        email    = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role     = data.get('role', 'analyst')

        email_ok, email_err = validate_email(email)
        if not email_ok:
            return jsonify({'error': email_err}), 400

        pass_ok, pass_err = validate_password(password)
        if not pass_ok:
            return jsonify({'error': pass_err}), 400

        if not username:
            username = email.split('@')[0]   # fallback: derive from email

        if role not in ('analyst', 'admin'):
            role = 'analyst'

        # Check duplicate email
        if db.get_user_by_identifier(email):
            return jsonify({'error': 'Email already registered'}), 409

        # Check duplicate username
        if db.get_user_by_identifier(username):
            return jsonify({'error': 'Username already taken'}), 409

        hashed  = hash_password(password)
        # FIX: pass username to DB so it's stored
        user_id = db.create_user(email, hashed, role, username=username)

        access_token  = create_access_token(
            identity=str(user_id),
            expires_delta=ACCESS_EXPIRES,
            additional_claims={'email': email, 'role': role, 'username': username}
        )
        refresh_token = create_refresh_token(
            identity=str(user_id),
            expires_delta=REFRESH_EXPIRES
        )

        logger.info(f"New user registered | id={user_id} | email={email} | username={username}")

        return jsonify({
            'message': 'Registration successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id':       user_id,
                'email':    email,
                'username': username,
                'role':     role,
            }
        }), 201

    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # FIX: login.html sends { username, password } — accept username OR email
        identifier = (
            data.get('username') or data.get('email') or ''
        ).strip()
        password   = data.get('password', '')
        remember   = data.get('remember_me', False)

        if not identifier or not password:
            return jsonify({'error': 'Username/email and password required'}), 400

        # Check account lock
        if db.is_account_locked(identifier):
            logger.warning(f"Login attempt on locked account: {identifier}")
            return jsonify({
                'error': 'Account temporarily locked due to too many failed attempts. Try again in 15 minutes.'
            }), 423

        # FIX: lookup by username OR email
        user = db.get_user_by_identifier(identifier)

        if not user or not verify_password(password, user['password']):
            attempts  = db.update_login_failure(identifier)
            remaining = max(0, MAX_ATTEMPTS - attempts)
            logger.warning(f"Failed login | identifier={identifier} | attempts={attempts}")
            return jsonify({
                'error': 'Invalid username/email or password',
                'attempts_remaining': remaining
            }), 401

        db.update_login_success(user['id'])

        access_expires  = REFRESH_EXPIRES if remember else ACCESS_EXPIRES
        refresh_expires = REFRESH_EXPIRES if remember else timedelta(days=1)

        access_token  = create_access_token(
            identity=str(user['id']),
            expires_delta=access_expires,
            additional_claims={
                'email':    user['email'],
                'username': user.get('username', ''),
                'role':     user['role'],
            }
        )
        refresh_token = create_refresh_token(
            identity=str(user['id']),
            expires_delta=refresh_expires
        )

        logger.info(f"Login success | id={user['id']} | identifier={identifier}")

        return jsonify({
            'message': 'Login successful',
            'access_token':  access_token,
            'refresh_token': refresh_token,
            'user': {
                'id':          user['id'],
                'email':       user['email'],
                'username':    user.get('username', ''),
                'role':        user['role'],
                'last_login':  user.get('last_login'),
                'login_count': user.get('login_count', 0),
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        user_id = get_jwt_identity()
        user    = db.get_user_by_id(int(user_id))

        if not user:
            return jsonify({'error': 'User not found'}), 404

        access_token = create_access_token(
            identity=user_id,
            expires_delta=ACCESS_EXPIRES,
            additional_claims={
                'email':    user['email'],
                'username': user.get('username', ''),
                'role':     user['role'],
            }
        )
        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'error': 'Token refresh failed'}), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    try:
        user_id = get_jwt_identity()
        user    = db.get_user_by_id(int(user_id))

        if not user:
            return jsonify({'error': 'User not found'}), 404

        stats = db.get_stats(int(user_id))

        return jsonify({
            'user': {
                'id':          user['id'],
                'email':       user['email'],
                'username':    user.get('username', ''),
                'role':        user['role'],
                'created_at':  user['created_at'],
                'last_login':  user.get('last_login'),
                'login_count': user.get('login_count', 0),
            },
            'stats': stats
        }), 200

    except Exception as e:
        logger.error(f"Profile fetch error: {e}")
        return jsonify({'error': 'Failed to fetch profile'}), 500


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        user_id = get_jwt_identity()

        # FIX: null check on data before .get()
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')

        if not old_password or not new_password:
            return jsonify({'error': 'Both old and new passwords required'}), 400

        user = db.get_user_by_id(int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # get full user record (includes hashed password)
        full_user = db.get_user_by_identifier(user['email'])
        if not verify_password(old_password, full_user['password']):
            return jsonify({'error': 'Current password is incorrect'}), 401

        pass_ok, pass_err = validate_password(new_password)
        if not pass_ok:
            return jsonify({'error': pass_err}), 400

        if old_password == new_password:
            return jsonify({'error': 'New password must be different'}), 400

        hashed = hash_password(new_password)

        # FIX: use proper public DB method instead of db._conn() private access
        db.update_password(int(user_id), hashed)

        logger.info(f"Password changed | user_id={user_id}")
        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        logger.error(f"Password change error: {e}")
        return jsonify({'error': 'Password change failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    logger.info(f"User logged out | id={user_id}")
    return jsonify({'message': 'Logged out successfully'}), 200
