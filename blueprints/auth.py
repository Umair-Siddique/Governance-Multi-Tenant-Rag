from flask import Blueprint, request, jsonify, current_app, redirect, make_response
from utils.auth_helpers import require_auth
import re
import uuid
import time
import requests as http_requests


auth_bp = Blueprint('auth', __name__)

# Temporary server-side PKCE store: {state_id -> {code_verifier, expires_at}}
# Entries expire after 10 minutes.
_pkce_store: dict = {}


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, None


def _get_user_by_email_direct(email: str):
    """
    Look up a Supabase auth user by email using a direct REST call to the
    GoTrue admin API (avoids list_users() which requires broader permissions).

    Returns a dict with at least {'id', 'email'}, or None if not found.
    """
    supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
    service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')

    if not supabase_url or not service_key:
        return None

    try:
        resp = http_requests.get(
            f"{supabase_url}/auth/v1/admin/users",
            params={'email': email, 'per_page': 1},
            headers={
                'Authorization': f'Bearer {service_key}',
                'apikey': service_key,
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        users = data.get('users', [])
        # The endpoint may return partial matches, so confirm exact email
        for u in users:
            if u.get('email', '').lower() == email.lower():
                return u
        return None

    except Exception as e:
        print(f"[auth] _get_user_by_email_direct failed: {e}")
        return None


@auth_bp.route('/register', methods=['POST'])
def register():
    """Create a new user account"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validate email
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500
        
        # Register user with Supabase Auth using admin API to bypass email sending
        # We'll handle email verification ourselves
        try:
            # Auto-generate tenant_id for the user (each user gets their own tenant)
            tenant_id = str(uuid.uuid4())
            
            # Registering users are always the admin/owner of their new tenant
            # Set role in both user_metadata and app_metadata for JWT token inclusion
            user_metadata = {
                'tenant_id': tenant_id,
                'role': 'admin'
            }
            app_metadata = {
                'provider': 'email',
                'providers': ['email'],
                'tenant_id': tenant_id,
                'role': 'admin'  # Also set in app_metadata for JWT token
            }
            
            # Use admin.create_user to bypass Supabase's email sending
            # This prevents rate limit issues
            # Note: Make sure email signups are enabled in Supabase Auth settings
            try:
                response = supabase.auth.admin.create_user({
                    'email': email,
                    'password': password,
                    'email_confirm': False,  # Don't auto-confirm - we'll verify via our own email
                    'user_metadata': user_metadata,
                    'app_metadata': app_metadata
                })
            except Exception as create_error:
                error_str = str(create_error)
                # Provide more helpful error messages
                if 'not allowed' in error_str.lower() or 'user not allowed' in error_str.lower():
                    return jsonify({
                        'error': 'User registration is not allowed. Please check Supabase Auth settings:',
                        'details': [
                            '1. Go to Supabase Dashboard > Authentication > Settings',
                            '2. Ensure "Enable email signup" is enabled',
                            '3. Check if there are any email domain restrictions',
                            '4. Verify your SUPABASE_SECRET_KEY has admin permissions'
                        ],
                        'original_error': error_str
                    }), 403
                raise  # Re-raise if it's a different error
            
            # Handle different response types
            user = response.user if hasattr(response, 'user') else response
            
            if not user:
                return jsonify({'error': 'Failed to create user account'}), 500
            
            # Generate our own verification token
            token_service = current_app.token_service
            verification_token = token_service.generate_verification_token(email)
            
            # Build verification URL (you can customize this based on your frontend)
            backend_url = current_app.config.get('BACKEND_URL', 'http://localhost:5001')
            verification_url = f"{backend_url}/auth/verify-email/{verification_token}"
            
            # Send verification email using our SMTP service
            email_service = current_app.email_service
            if email_service:
                email_sent = email_service.send_verification_email(email, verification_url)
                
                if not email_sent:
                    # Email failed to send, but user was created
                    return jsonify({
                        'message': 'Account created but failed to send verification email. Please contact support.',
                        'user': {
                            'id': user.id,
                            'email': user.email,
                            'tenant_id': tenant_id,
                            'email_confirmed_at': None,
                            'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') and user.created_at else None
                        },
                        'requires_verification': True,
                        'note': 'Contact support to resend verification email'
                    }), 201
            else:
                # Email service not configured
                return jsonify({
                    'error': 'Email service not configured',
                    'message': 'Please contact administrator to configure email service'
                }), 500
            
            return jsonify({
                'message': 'Account created successfully! Please check your email to verify your account.',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'tenant_id': tenant_id,
                    'email_confirmed_at': None,
                    'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') and user.created_at else None
                },
                'requires_verification': True,
                'note': 'You must verify your email before signing in'
            }), 201
            
        except Exception as e:
            error_msg = str(e)
            
            # Handle Supabase-specific errors
            if 'User already registered' in error_msg or 'already registered' in error_msg.lower() or 'already exists' in error_msg.lower():
                return jsonify({'error': 'An account with this email already exists'}), 409
            
            if 'Invalid email' in error_msg or 'invalid' in error_msg.lower():
                return jsonify({'error': 'Invalid email address'}), 400
            
            return jsonify({'error': f'Registration failed: {error_msg}'}), 400
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/signin', methods=['POST'])
def signin():
    """Sign in with email and password"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validate inputs
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500
        
        # Sign in with Supabase Auth
        try:
            response = supabase.auth.sign_in_with_password({
                'email': email,
                'password': password
            })
            
            user = response.user
            session = response.session
            
            if not user or not session:
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Check if email is verified
            if not user.email_confirmed_at:
                return jsonify({
                    'error': 'Email not verified. Please check your email and verify your account.',
                    'requires_verification': True
                }), 403
            
            # Extract tenant_id and role from user metadata
            user_metadata = getattr(user, 'user_metadata', {}) or {}
            tenant_id = user_metadata.get('tenant_id')
            role = user_metadata.get('role', 'user')

            # If not in user_metadata, try app_metadata
            if not tenant_id:
                app_metadata = getattr(user, 'app_metadata', {}) or {}
                tenant_id = app_metadata.get('tenant_id')

            # ── Lazy Pinecone init ──────────────────────────────────────────
            # Create the tenant's Pinecone index on first successful sign-in
            # only if one hasn't been provisioned yet.
            if tenant_id:
                pinecone_service = current_app.pinecone_service
                if pinecone_service:
                    try:
                        db_result = current_app.supabase_client \
                            .table('tenants') \
                            .select('pinecone_index_name') \
                            .eq('id', tenant_id) \
                            .execute()
                        already_provisioned = (
                            db_result.data
                            and db_result.data[0].get('pinecone_index_name')
                        )
                        if not already_provisioned:
                            pinecone_service.create_tenant_index(tenant_id, store_in_db=True)
                    except Exception as pinecone_error:
                        # Non-fatal – log and continue
                        print(f"⚠️  Pinecone lazy-init failed for tenant {tenant_id}: {pinecone_error}")
            # ───────────────────────────────────────────────────────────────

            return jsonify({
                'message': 'Sign in successful',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'tenant_id': tenant_id,
                    'role': role,
                    'email_confirmed_at': user.email_confirmed_at.isoformat() if user.email_confirmed_at else None,
                    'created_at': user.created_at.isoformat() if user.created_at else None
                },
                'session': {
                    'access_token': session.access_token,
                    'refresh_token': session.refresh_token,
                    'expires_at': session.expires_at,
                    'expires_in': session.expires_in,
                    'token_type': session.token_type
                }
            }), 200
            
        except Exception as e:
            error_msg = str(e)
            
            # Handle Supabase-specific errors
            if 'Invalid login credentials' in error_msg or 'invalid' in error_msg.lower():
                return jsonify({'error': 'Invalid email or password'}), 401
            
            if 'Email not confirmed' in error_msg or 'not confirmed' in error_msg.lower():
                return jsonify({
                    'error': 'Email not verified. Please check your email and verify your account.',
                    'requires_verification': True
                }), 403
            
            return jsonify({'error': f'Sign in failed: {error_msg}'}), 400
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/google-signin', methods=['GET'])
def google_signin():
    """
    Start Google OAuth (PKCE) sign-in via Supabase.
    No request body or params required.

    ?format=json  — returns JSON {auth_url, state} instead of redirecting.
                    Use state when calling POST /auth/google-callback.

    Browser flow  — redirects directly to Google. A short-lived HttpOnly cookie
                    (pkce_code_verifier) is set so the callback can exchange the code.
    """
    try:
        # Purge expired PKCE entries on each call (lightweight housekeeping)
        now = time.time()
        expired_keys = [k for k, v in _pkce_store.items() if v['expires_at'] < now]
        for k in expired_keys:
            _pkce_store.pop(k, None)

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500

        try:
            redirect_to = current_app.config.get('FRONTEND_URL') or current_app.config.get('BACKEND_URL')
            oauth_payload = {'provider': 'google'}
            if redirect_to:
                oauth_payload['options'] = {'redirect_to': redirect_to}

            response = supabase.auth.sign_in_with_oauth(oauth_payload)
        except Exception as e:
            return jsonify({'error': f'Google OAuth start failed: {str(e)}'}), 400

        # Extract auth URL
        auth_url = None
        if isinstance(response, dict):
            auth_url = response.get('url') or ((response.get('data') or {}).get('url'))
        else:
            auth_url = getattr(response, 'url', None)
            if not auth_url and hasattr(response, 'data'):
                response_data = getattr(response, 'data', None) or {}
                if isinstance(response_data, dict):
                    auth_url = response_data.get('url')

        if not auth_url:
            return jsonify({
                'error': 'Failed to generate Google OAuth URL',
                'details': 'Supabase did not return an OAuth URL'
            }), 500

        # Extract PKCE code_verifier produced by the Supabase client
        code_verifier = getattr(response, 'code_verifier', None)
        if not code_verifier and isinstance(response, dict):
            code_verifier = response.get('code_verifier')

        # Store code_verifier server-side keyed by a state_id (10-min TTL)
        state_id = str(uuid.uuid4())
        if code_verifier:
            _pkce_store[state_id] = {
                'code_verifier': code_verifier,
                'expires_at':    now + 600,
            }

        # ── JSON mode (API / curl testing) ───────────────────────────────
        if request.args.get('format') == 'json':
            return jsonify({
                'message': 'Open auth_url in a browser to continue Google sign in',
                'auth_url': auth_url,
                'state':    state_id if code_verifier else None,
            }), 200

        # ── Browser redirect mode ─────────────────────────────────────────
        # Set code_verifier in an HttpOnly cookie so the frontend can include
        # it (or the state_id) when calling POST /auth/google-callback.
        resp = make_response(redirect(auth_url, code=302))
        if code_verifier:
            resp.set_cookie(
                'pkce_code_verifier',
                code_verifier,
                max_age=600,
                httponly=True,
                samesite='Lax',
            )
        return resp

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/google-callback', methods=['POST'])
def google_callback():
    """
    Exchange the OAuth authorization code returned by Google/Supabase for a
    full session (access_token, refresh_token, user info).

    Frontend calls this after being redirected back with ?code=...

    Body (pick one):
        { "code": "...", "state": "<state returned by /auth/google-signin?format=json>" }
        { "code": "...", "code_verifier": "<verifier returned by /auth/google-signin?format=json>" }

    Returns the same shape as POST /auth/signin.
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        code = (data.get('code') or '').strip()
        if not code:
            return jsonify({'error': 'code is required'}), 400

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500

        # ── Resolve code_verifier (PKCE) ─────────────────────────────────
        # Priority: body code_verifier > body state > cookie
        code_verifier = (data.get('code_verifier') or '').strip() or None

        if not code_verifier:
            state_id = (data.get('state') or '').strip()
            if state_id:
                entry = _pkce_store.pop(state_id, None)
                if entry and entry['expires_at'] > time.time():
                    code_verifier = entry['code_verifier']

        if not code_verifier:
            code_verifier = request.cookies.get('pkce_code_verifier') or None

        # ── Exchange code for session ────────────────────────────────────
        exchange_payload = {'auth_code': code}
        if code_verifier:
            exchange_payload['code_verifier'] = code_verifier

        try:
            response = supabase.auth.exchange_code_for_session(exchange_payload)
        except Exception as e:
            return jsonify({'error': f'Code exchange failed: {str(e)}'}), 401

        user = getattr(response, 'user', None)
        session = getattr(response, 'session', None)

        if not user or not session:
            return jsonify({'error': 'Failed to exchange code for session'}), 401

        user_metadata = getattr(user, 'user_metadata', {}) or {}
        app_metadata  = getattr(user, 'app_metadata',  {}) or {}
        tenant_id = user_metadata.get('tenant_id') or app_metadata.get('tenant_id')
        role      = user_metadata.get('role')      or app_metadata.get('role') or 'user'

        # ── Bootstrap tenant on first Google sign-in ─────────────────────
        # Fatal if it fails — without tenant_id every protected API returns 403.
        # Note: no session re-issue needed because require_auth calls
        # supabase.auth.get_user(token) which reads live DB metadata, not JWT claims.
        if not tenant_id:
            tenant_id = str(uuid.uuid4())
            role = 'admin'
            existing_providers = app_metadata.get('providers') or []
            if isinstance(existing_providers, str):
                existing_providers = [existing_providers]

            updated_user_metadata = {**user_metadata, 'tenant_id': tenant_id, 'role': role}
            updated_app_metadata  = {
                **app_metadata,
                'provider':  'google',
                'providers': sorted(set(existing_providers + ['google'])),
                'tenant_id': tenant_id,
                'role':      role,
            }

            supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
            service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')
            user_id      = str(user.id)

            # GoTrue admin route only accepts PUT (not PATCH) for full user updates
            put_resp = http_requests.put(
                f"{supabase_url}/auth/v1/admin/users/{user_id}",
                json={
                    'user_metadata': updated_user_metadata,
                    'app_metadata':  updated_app_metadata,
                },
                headers={
                    'Authorization': f'Bearer {service_key}',
                    'apikey':        service_key,
                    'Content-Type':  'application/json',
                },
                timeout=10,
            )

            if put_resp.status_code not in (200, 201):
                try:
                    err = put_resp.json().get('message') or put_resp.text
                except Exception:
                    err = put_resp.text or f'HTTP {put_resp.status_code}'
                return jsonify({
                    'error': f'Failed to set up tenant for Google account: {err}'
                }), 500

        # ── Lazy Pinecone init (same as email signin) ─────────────────────
        if tenant_id:
            pinecone_service = current_app.pinecone_service
            if pinecone_service:
                try:
                    db_result = current_app.supabase_client \
                        .table('tenants') \
                        .select('pinecone_index_name') \
                        .eq('id', tenant_id) \
                        .execute()
                    already_provisioned = (
                        db_result.data and db_result.data[0].get('pinecone_index_name')
                    )
                    if not already_provisioned:
                        pinecone_service.create_tenant_index(tenant_id, store_in_db=True)
                except Exception as pinecone_error:
                    print(f"⚠️  Pinecone lazy-init failed for tenant {tenant_id}: {pinecone_error}")

        def _iso(val):
            if not val:
                return None
            return val.isoformat() if hasattr(val, 'isoformat') else str(val)

        return jsonify({
            'message': 'Google sign in successful',
            'user': {
                'id':                 user.id,
                'email':              user.email,
                'tenant_id':          tenant_id,
                'role':               role,
                'email_confirmed_at': _iso(getattr(user, 'email_confirmed_at', None)),
                'created_at':         _iso(getattr(user, 'created_at', None)),
            },
            'session': {
                'access_token':  session.access_token,
                'refresh_token': session.refresh_token,
                'expires_at':    session.expires_at,
                'expires_in':    session.expires_in,
                'token_type':    session.token_type,
            }
        }), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email_token(token):
    """Verify email using token from email link"""
    try:
        # Get token service
        token_service = current_app.token_service
        if not token_service:
            return jsonify({'error': 'Token service not configured'}), 500
        
        # Verify token and extract email
        email, error = token_service.verify_token(token)
        
        if error:
            return jsonify({'error': error}), 400
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500
        
        try:
            # Look up the user by email without calling list_users()
            user_to_verify = _get_user_by_email_direct(email)

            if not user_to_verify:
                return jsonify({'error': 'User not found'}), 404

            user_id = user_to_verify.get('id')
            if not user_id:
                return jsonify({'error': 'Could not resolve user account'}), 500

            # Update user to confirm email
            supabase.auth.admin.update_user_by_id(
                user_id,
                {'email_confirm': True}
            )
            
            # Send welcome email
            email_service = current_app.email_service
            if email_service:
                email_service.send_welcome_email(email)
            
            return jsonify({
                'message': 'Email verified successfully! You can now sign in.',
                'email': email
            }), 200
            
        except Exception as e:
            error_msg = str(e)
            return jsonify({'error': f'Failed to verify email: {error_msg}'}), 400
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend email verification"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500
        
        try:
            # Check if user exists using targeted API call (avoids list_users())
            user = _get_user_by_email_direct(email)

            if not user:
                return jsonify({'error': 'No account found with this email'}), 404

            user_confirmed = bool(user.get('email_confirmed_at'))
            if user_confirmed:
                return jsonify({'error': 'Email is already verified'}), 400
            
            # Generate new verification token
            token_service = current_app.token_service
            verification_token = token_service.generate_verification_token(email)
            
            # Build verification URL
            backend_url = current_app.config.get('BACKEND_URL')
            verification_url = f"{backend_url}/auth/verify-email/{verification_token}"
            
            # Send verification email
            email_service = current_app.email_service
            if not email_service:
                return jsonify({'error': 'Email service not configured'}), 500
            
            email_sent = email_service.send_verification_email(email, verification_url)
            
            if not email_sent:
                return jsonify({'error': 'Failed to send verification email'}), 500
            
            return jsonify({
                'message': 'Verification email sent. Please check your inbox.'
            }), 200
            
        except Exception as e:
            error_msg = str(e)
            return jsonify({'error': f'Failed to send verification email: {error_msg}'}), 400
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Send password reset link to email if account exists"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        email = data.get('email', '').strip().lower()

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Get required services
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Authentication service not configured'}), 500

        token_service = current_app.token_service
        if not token_service:
            return jsonify({'error': 'Token service not configured'}), 500

        email_service = current_app.email_service
        if not email_service:
            return jsonify({'error': 'Email service not configured'}), 500

        try:
            # Look up the user with a targeted API call (avoids list_users()).
            # We still only send the email when the account exists, but we
            # always return the same response to prevent email enumeration.
            user = _get_user_by_email_direct(email)

            if user:
                reset_token = token_service.generate_password_reset_token(email)
                # Send the token to the frontend; the frontend will include it
                # in the Authorization header when calling POST /auth/reset-password
                frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
                reset_url = f"{frontend_url}/reset-password?token={reset_token}"
                email_service.send_password_reset_email(email, reset_url)

            return jsonify({
                'message': 'If an account exists for this email, a password reset link has been sent.'
            }), 200

        except Exception as e:
            error_msg = str(e)
            return jsonify({'error': f'Failed to process password reset request: {error_msg}'}), 400

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset user password.

    The signed reset token must be supplied in the Authorization header:
        Authorization: Bearer <reset_token>

    Body:
        { "password": "NewSecurePass1" }
    """
    try:
        # ── 1. Extract token from Authorization header ──────────────────
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Reset token required. Supply it as: Authorization: Bearer <token>'}), 400
        token = auth_header[len('Bearer '):]

        # ── 2. Validate new password ────────────────────────────────────
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        new_password = data.get('password', '')
        if not new_password:
            return jsonify({'error': 'Password is required'}), 400

        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        # ── 3. Verify token → extract email ─────────────────────────────
        token_service = current_app.token_service
        if not token_service:
            return jsonify({'error': 'Token service not configured'}), 500

        email, token_error = token_service.verify_password_reset_token(token)
        if token_error:
            return jsonify({'error': token_error}), 400

        # ── 4. Look up user by email (targeted REST call, no list_users) ─
        user = _get_user_by_email_direct(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        user_id = user.get('id')
        if not user_id:
            return jsonify({'error': 'Could not resolve user account'}), 500

        # ── 5. Update password via direct REST call ─────────────────────
        #    supabase.auth.admin.update_user_by_id() is avoided because it
        #    triggers "User not allowed" in some Supabase configurations.
        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')

        resp = http_requests.put(
            f"{supabase_url}/auth/v1/admin/users/{user_id}",
            json={'password': new_password},
            headers={
                'Authorization': f'Bearer {service_key}',
                'apikey': service_key,
                'Content-Type': 'application/json',
            },
            timeout=10,
        )

        if resp.status_code not in (200, 201):
            try:
                err = resp.json().get('message') or resp.text
            except Exception:
                err = resp.text or f'HTTP {resp.status_code}'
            return jsonify({'error': f'Failed to reset password: {err}'}), 400

        return jsonify({
            'message': 'Password reset successful. You can now sign in with your new password.'
        }), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


