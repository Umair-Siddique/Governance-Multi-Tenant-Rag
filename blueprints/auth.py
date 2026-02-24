from flask import Blueprint, request, jsonify, current_app, redirect, make_response
from utils.auth_helpers import require_auth
from types import SimpleNamespace
from datetime import datetime
import base64
import hashlib
import secrets
import re
import uuid
import time
import urllib.parse
import requests as http_requests


auth_bp = Blueprint('auth', __name__)


def _exchange_code_http(supabase_url, service_key, auth_code, code_verifier=None):
    """
    Exchange an OAuth authorization code for a Supabase session via direct
    HTTP instead of supabase.auth.exchange_code_for_session().

    WHY: The supabase-py SDK stores the returned session on the shared client
    and fires an auth-state listener that replaces the PostgREST Authorization
    header with the user's JWT.  Every table() call after that runs under RLS
    (user context) instead of the service-role key, causing policy violations.
    Using HTTP directly leaves the shared admin client completely untouched.

    Returns a SimpleNamespace(user=..., session=...) that mirrors the SDK
    response shape so existing code needs no changes.
    """
    body = {'auth_code': auth_code}
    if code_verifier:
        body['code_verifier'] = code_verifier

    resp = http_requests.post(
        f"{supabase_url}/auth/v1/token?grant_type=pkce",
        json=body,
        headers={
            'apikey':        service_key,
            'Content-Type':  'application/json',
        },
        timeout=15,
    )

    if resp.status_code != 200:
        try:
            msg = resp.json().get('error_description') or resp.json().get('msg') or resp.text
        except Exception:
            msg = resp.text or f'HTTP {resp.status_code}'
        raise Exception(msg)

    data = resp.json()
    raw  = data.get('user') or {}

    def _dt(val):
        if not val:
            return None
        try:
            return datetime.fromisoformat(val.replace('Z', '+00:00'))
        except Exception:
            return val

    user = SimpleNamespace(
        id                 = raw.get('id'),
        email              = raw.get('email', ''),
        user_metadata      = raw.get('user_metadata') or {},
        app_metadata       = raw.get('app_metadata')  or {},
        email_confirmed_at = _dt(raw.get('email_confirmed_at')),
        created_at         = _dt(raw.get('created_at')),
    )
    session = SimpleNamespace(
        access_token  = data.get('access_token'),
        refresh_token = data.get('refresh_token'),
        expires_in    = data.get('expires_in'),
        expires_at    = data.get('expires_at'),
        token_type    = data.get('token_type', 'bearer'),
    )
    return SimpleNamespace(user=user, session=session)


def _create_user_admin_http(supabase_url, service_key, email, password, user_metadata, app_metadata):
    """
    Create an Auth user through GoTrue admin REST directly.

    Using HTTP here avoids SDK auth-state side effects on the shared client.
    """
    resp = http_requests.post(
        f"{supabase_url}/auth/v1/admin/users",
        json={
            'email': email,
            'password': password,
            'email_confirm': False,
            'user_metadata': user_metadata,
            'app_metadata': app_metadata,
        },
        headers={
            'Authorization': f'Bearer {service_key}',
            'apikey': service_key,
            'Content-Type': 'application/json',
        },
        timeout=15,
    )

    if resp.status_code not in (200, 201):
        try:
            payload = resp.json()
            msg = (
                payload.get('msg')
                or payload.get('message')
                or payload.get('error_description')
                or payload.get('error')
                or str(payload)
            )
        except Exception:
            msg = resp.text or f'HTTP {resp.status_code}'
        raise Exception(msg)

    raw = resp.json() or {}
    created_at = raw.get('created_at')
    try:
        created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00')) if created_at else None
    except Exception:
        pass

    return SimpleNamespace(
        id=raw.get('id'),
        email=raw.get('email', ''),
        created_at=created_at,
    )


def _b64url_no_padding(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def _generate_pkce_pair():
    # RFC 7636 code_verifier: 43-128 chars from unreserved URL charset.
    code_verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = _b64url_no_padding(digest)
    return code_verifier, code_challenge


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
        
        # Use direct GoTrue admin REST for registration to avoid SDK auth-state
        # side effects when the shared Supabase client has user sessions.
        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key = current_app.config.get('SUPABASE_SECRET_KEY', '')
        if not supabase_url or not service_key:
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
            
            try:
                user = _create_user_admin_http(
                    supabase_url=supabase_url,
                    service_key=service_key,
                    email=email,
                    password=password,
                    user_metadata=user_metadata,
                    app_metadata=app_metadata
                )
            except Exception as create_error:
                error_str = str(create_error)
                # Provide more helpful error messages
                if 'not allowed' in error_str.lower() or 'user not allowed' in error_str.lower():
                    return jsonify({
                        'error': 'User registration request was rejected by Supabase.',
                        'details': [
                            '1. Verify SUPABASE_SECRET_KEY is the service_role key (not anon/public key)',
                            '2. Confirm Auth settings do not block this email/domain',
                            '3. Check if a custom Auth hook or external provider policy is rejecting signups',
                            '4. Review original_error for the exact Supabase rejection reason'
                        ],
                        'original_error': error_str
                    }), 403
                raise  # Re-raise if it's a different error
            
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

        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        if not supabase_url:
            return jsonify({'error': 'Authentication service not configured'}), 500

        frontend_url = (
            current_app.config.get('FRONTEND_URL')
            or current_app.config.get('BACKEND_URL', '')
        ).rstrip('/')
        redirect_to = f"{frontend_url}/auth/callback" if frontend_url else None

        # Build PKCE pair on the server so we always have a verifier to
        # exchange with /auth/google-callback (works for curl and browser flows).
        code_verifier, code_challenge = _generate_pkce_pair()
        state_id = str(uuid.uuid4())
        _pkce_store[state_id] = {
            'code_verifier': code_verifier,
            'expires_at':    now + 600,
        }

        params = {
            'provider': 'google',
            'code_challenge': code_challenge,
            'code_challenge_method': 's256',
        }
        if redirect_to:
            params['redirect_to'] = redirect_to
        auth_url = f"{supabase_url}/auth/v1/authorize?{urllib.parse.urlencode(params)}"

        # JSON mode for API/curl testing
        if request.args.get('format') == 'json':
            return jsonify({
                'message': 'Open auth_url in a browser to continue Google sign in',
                'auth_url': auth_url,
                'state': state_id,
            }), 200

        # Browser redirect mode
        resp = make_response(redirect(auth_url, code=302))
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

        # ── Exchange code for session (HTTP, not SDK, to keep admin client clean) ──
        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')
        try:
            response = _exchange_code_http(supabase_url, service_key, code, code_verifier)
        except Exception as e:
            return jsonify({'error': f'Code exchange failed: {str(e)}'}), 401

        user    = response.user
        session = response.session

        if not user or not session:
            return jsonify({'error': 'Failed to exchange code for session'}), 401

        user_metadata = getattr(user, 'user_metadata', {}) or {}
        app_metadata  = getattr(user, 'app_metadata',  {}) or {}
        tenant_id = user_metadata.get('tenant_id') or app_metadata.get('tenant_id')
        role      = user_metadata.get('role')      or app_metadata.get('role') or 'user'

        # ── Bootstrap tenant on first Google sign-in ─────────────────────
        # Fatal if it fails — without tenant_id every protected API returns 403.
        google_bootstrapped = False
        if not tenant_id:
            tenant_id = str(uuid.uuid4())
            role = 'admin'
            google_bootstrapped = True
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

        # After bootstrap the original JWT has no tenant_id in its claims.
        # Refresh to get a new JWT that includes the updated metadata so that
        # Supabase RLS policies work immediately without requiring a second login.
        new_tok = _refresh_session_tokens(session) if google_bootstrapped else None

        def _gtok(field, fallback):
            return (new_tok or {}).get(field) or getattr(session, field, fallback)

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
                'access_token':  _gtok('access_token',  session.access_token),
                'refresh_token': _gtok('refresh_token', session.refresh_token),
                'expires_at':    _gtok('expires_at',    session.expires_at),
                'expires_in':    _gtok('expires_in',    session.expires_in),
                'token_type':    _gtok('token_type',    session.token_type),
            }
        }), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/azure-signin', methods=['GET'])
def azure_signin():
    """
    Start Microsoft Entra ID (Azure AD) OIDC sign-in via Supabase.

    The OAuth callback is routed through the BACKEND (not the frontend) so the
    server can exchange the code itself. This avoids the browser-side PKCE
    mismatch that causes "session=expired" when OAuth is initiated server-side.

    After a successful exchange the backend redirects the browser to:
        {FRONTEND_URL}/auth/callback#access_token=...&refresh_token=...&...

    ?format=json  — returns JSON { auth_url } instead of a browser redirect.
                    Useful for testing with curl.
    """
    try:
        now = time.time()
        expired_keys = [k for k, v in _pkce_store.items() if v['expires_at'] < now]
        for k in expired_keys:
            _pkce_store.pop(k, None)

        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        if not supabase_url:
            return jsonify({'error': 'Authentication service not configured'}), 500

        # Redirect back to OUR backend so we can do the code exchange server-side.
        # The backend then redirects the browser to the frontend with the final tokens.
        backend_url = current_app.config.get('BACKEND_URL', '').rstrip('/')
        # In JSON/test mode, embed ?format=json in redirect_to so the callback
        # returns a JSON response (tokens visible in browser) instead of a frontend redirect.
        json_mode = request.args.get('format') == 'json'
        callback_path = '/auth/azure-callback?format=json' if json_mode else '/auth/azure-callback'
        # Build PKCE pair on the server so callback can always exchange code.
        # We attach a custom OAuth state value and also store verifier server-side.
        code_verifier, code_challenge = _generate_pkce_pair()
        state_id = str(uuid.uuid4())
        _pkce_store[state_id] = {
            'code_verifier': code_verifier,
            'expires_at':    now + 600,
        }

        # Pass our own PKCE lookup key using a custom query param in redirect_to.
        # Do NOT use OAuth "state" for this; Supabase uses state internally and
        # overriding it can trigger bad_oauth_state.
        redirect_to_with_pkce = f"{backend_url}{callback_path}"
        joiner = '&' if '?' in redirect_to_with_pkce else '?'
        redirect_to_with_pkce = f"{redirect_to_with_pkce}{joiner}pkce_state={urllib.parse.quote(state_id)}"

        params = {
            'provider': 'azure',
            'redirect_to': redirect_to_with_pkce,
            'scope': 'openid email profile offline_access',
            'code_challenge': code_challenge,
            'code_challenge_method': 's256',
        }
        auth_url = f"{supabase_url}/auth/v1/authorize?{urllib.parse.urlencode(params)}"

        if json_mode:
            return jsonify({
                'message': 'Open auth_url in a browser to start Microsoft sign-in. '
                           'After authenticating, the browser will show your access_token as JSON.',
                'auth_url': auth_url,
                'pkce_state': state_id,
            }), 200

        resp = make_response(redirect(auth_url, code=302))
        # Cookie lets the GET callback retrieve verifier in normal browser flow.
        resp.set_cookie(
            'azure_pkce_state',
            state_id,
            max_age=600,
            httponly=True,
            samesite='Lax',
        )
        return resp

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


def _refresh_session_tokens(original_session):
    """
    After writing tenant_id into user_metadata/app_metadata via the admin API,
    the original JWT still reflects the old (pre-bootstrap) state.  Calling this
    forces Supabase to issue a brand-new JWT that embeds the updated metadata so
    that RLS policies (which read auth.jwt()) work immediately.

    Returns a plain dict with the new token fields, or None if the refresh fails
    (caller should fall back to original_session in that case).
    """
    supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
    service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')
    refresh_token = getattr(original_session, 'refresh_token', None)

    if not refresh_token:
        return None

    try:
        resp = http_requests.post(
            f"{supabase_url}/auth/v1/token?grant_type=refresh_token",
            json={'refresh_token': refresh_token},
            headers={
                'apikey':        service_key,
                'Content-Type':  'application/json',
            },
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        print(f"[auth] session refresh HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[auth] session refresh failed: {e}")

    return None


def _resolve_azure_email(user, user_metadata):
    """
    Microsoft sometimes returns an empty email in the OIDC token even when
    preferred_username holds the actual address. This function:
      1. Returns user.email if it is non-empty.
      2. Otherwise falls back to preferred_username / email from user_metadata.
      3. Patches the Supabase auth record so the user is visible in the dashboard.

    Returns the resolved email string (may still be '' if Microsoft gave nothing).
    """
    email = (getattr(user, 'email', '') or '').strip()
    if email:
        return email

    # Try common Microsoft OIDC claim aliases
    fallback = (
        user_metadata.get('preferred_username') or
        user_metadata.get('email') or
        user_metadata.get('upn') or
        ''
    ).strip()

    if not fallback:
        return ''

    # Patch the Supabase user record so the dashboard shows the email
    try:
        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')
        http_requests.put(
            f"{supabase_url}/auth/v1/admin/users/{user.id}",
            json={'email': fallback, 'email_confirm': True},
            headers={
                'Authorization': f'Bearer {service_key}',
                'apikey':        service_key,
                'Content-Type':  'application/json',
            },
            timeout=10,
        )
        print(f"[azure] patched empty email → {fallback} for user {user.id}")
    except Exception as patch_err:
        print(f"[azure] email patch failed for user {user.id}: {patch_err}")

    return fallback


def _bootstrap_azure_tenant(user, user_metadata, app_metadata):
    """
    Assign a new tenant_id + admin role to a first-time Microsoft sign-in user.
    Returns (tenant_id, role) or raises on failure.
    """
    tenant_id = str(uuid.uuid4())
    role = 'admin'
    existing_providers = app_metadata.get('providers') or []
    if isinstance(existing_providers, str):
        existing_providers = [existing_providers]

    updated_user_metadata = {**user_metadata, 'tenant_id': tenant_id, 'role': role}
    updated_app_metadata  = {
        **app_metadata,
        'provider':  'azure',
        'providers': sorted(set(existing_providers + ['azure'])),
        'tenant_id': tenant_id,
        'role':      role,
    }

    supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
    service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')

    put_resp = http_requests.put(
        f"{supabase_url}/auth/v1/admin/users/{user.id}",
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
        raise RuntimeError(f'Failed to set up tenant for Microsoft account: {err}')

    return tenant_id, role


def _lazy_pinecone_init(tenant_id):
    """Create a Pinecone index for the tenant if one doesn't exist yet."""
    pinecone_service = current_app.pinecone_service
    if not pinecone_service:
        return
    try:
        db_result = (
            current_app.supabase_client
            .table('tenants')
            .select('pinecone_index_name')
            .eq('id', tenant_id)
            .execute()
        )
        already_provisioned = db_result.data and db_result.data[0].get('pinecone_index_name')
        if not already_provisioned:
            pinecone_service.create_tenant_index(tenant_id, store_in_db=True)
    except Exception as pinecone_error:
        print(f"⚠️  Pinecone lazy-init failed for tenant {tenant_id}: {pinecone_error}")


@auth_bp.route('/azure-callback', methods=['GET'])
def azure_callback_redirect():
    """
    GET — called by Supabase after Microsoft authenticates the user.

    Supabase redirects the browser here with ?code=... (and optionally ?error=...).
    We exchange the code for a Supabase session, bootstrap the tenant when needed,
    and then redirect the browser to the frontend with the session tokens in the
    URL fragment so the frontend can store them exactly as it does for other providers.

    Frontend destination:
        {FRONTEND_URL}/auth/callback#access_token=...&refresh_token=...&tenant_id=...&role=...
    """
    frontend_url = current_app.config.get('FRONTEND_URL', '').rstrip('/')
    json_mode = request.args.get('format') == 'json'

    def _error_redirect(msg):
        if json_mode:
            return jsonify({'error': msg}), 400
        return redirect(
            f"{frontend_url}/auth/callback?error={urllib.parse.quote(msg)}",
            code=302,
        )

    try:
        error = request.args.get('error', '')
        if error:
            desc = request.args.get('error_description', error)
            return _error_redirect(desc)

        code = request.args.get('code', '').strip()
        if not code:
            return _error_redirect('missing_code')

        supabase = current_app.supabase_client
        if not supabase:
            return _error_redirect('service_unavailable')

        # Recover PKCE verifier from:
        # 1) cookie state (browser redirect flow), or
        # 2) query pkce_state (format=json flow where auth_url is opened directly)
        code_verifier = None
        state_id = request.cookies.get('azure_pkce_state', '') or request.args.get('pkce_state', '').strip()
        if state_id:
            entry = _pkce_store.pop(state_id, None)
            if entry and entry['expires_at'] > time.time():
                code_verifier = entry['code_verifier']

        supabase_url_cfg = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key_cfg  = current_app.config.get('SUPABASE_SECRET_KEY', '')
        try:
            response = _exchange_code_http(supabase_url_cfg, service_key_cfg, code, code_verifier)
        except Exception as e:
            return _error_redirect(f'exchange_failed: {str(e)}')

        user    = response.user
        session = response.session
        if not user or not session:
            return _error_redirect('no_session')

        user_metadata = getattr(user, 'user_metadata', {}) or {}
        app_metadata  = getattr(user, 'app_metadata',  {}) or {}
        tenant_id = user_metadata.get('tenant_id') or app_metadata.get('tenant_id')
        role      = user_metadata.get('role')      or app_metadata.get('role') or 'user'

        # Resolve email — Microsoft may return empty email; fall back to preferred_username
        resolved_email = _resolve_azure_email(user, user_metadata)

        bootstrapped = False
        if not tenant_id:
            try:
                tenant_id, role = _bootstrap_azure_tenant(user, user_metadata, app_metadata)
                bootstrapped = True
            except RuntimeError as e:
                return _error_redirect(str(e))

        # After bootstrap the original JWT has no tenant_id in its claims yet.
        # Refresh the session so the new JWT embeds the updated metadata and
        # Supabase RLS policies (which read auth.jwt()) work immediately.
        if bootstrapped:
            new_tok = _refresh_session_tokens(session)
        else:
            new_tok = None

        def _tok(field, fallback):
            return (new_tok or {}).get(field) or getattr(session, field, fallback)

        _lazy_pinecone_init(tenant_id)

        def _iso(val):
            if not val:
                return None
            return val.isoformat() if hasattr(val, 'isoformat') else str(val)

        # JSON mode — return tokens as JSON (same shape as POST /auth/signin)
        # Triggered when redirect_to had ?format=json embedded (curl / API testing)
        if request.args.get('format') == 'json':
            resp = jsonify({
                'message': 'Microsoft sign-in successful',
                'user': {
                    'id':                 user.id,
                    'email':              resolved_email,
                    'tenant_id':          tenant_id,
                    'role':               role,
                    'email_confirmed_at': _iso(getattr(user, 'email_confirmed_at', None)),
                    'created_at':         _iso(getattr(user, 'created_at', None)),
                },
                'session': {
                    'access_token':  _tok('access_token',  session.access_token),
                    'refresh_token': _tok('refresh_token', session.refresh_token),
                    'expires_at':    _tok('expires_at',    session.expires_at),
                    'expires_in':    _tok('expires_in',    session.expires_in),
                    'token_type':    _tok('token_type',    session.token_type),
                },
            })
            resp.delete_cookie('azure_pkce_state')
            return resp, 200

        # Browser mode — redirect to frontend with tokens in URL fragment
        # (frontend reads window.location.hash and stores them)
        fragment = urllib.parse.urlencode({
            'access_token':  _tok('access_token',  session.access_token),
            'refresh_token': _tok('refresh_token', session.refresh_token),
            'expires_in':    _tok('expires_in',    session.expires_in),
            'token_type':    _tok('token_type',    session.token_type),
            'tenant_id':     tenant_id,
            'role':          role,
        })
        resp = redirect(f"{frontend_url}/auth/callback#{fragment}", code=302)
        resp.delete_cookie('azure_pkce_state')
        return resp

    except Exception as e:
        return _error_redirect(f'internal_error: {str(e)}')


@auth_bp.route('/azure-callback', methods=['POST'])
def azure_callback_api():
    """
    POST — direct API endpoint for testing or custom frontend integrations.

    Accepts a raw authorization code and returns a JSON session (same shape as
    POST /auth/signin). Use this when the frontend handles the code redirect
    itself instead of relying on the GET handler above.

    Body (pick one):
        { "code": "...", "state": "<state_id from server-side PKCE store>" }
        { "code": "...", "code_verifier": "<raw PKCE verifier>" }
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

        # Resolve code_verifier: body > state_id lookup > cookie
        code_verifier = (data.get('code_verifier') or '').strip() or None
        if not code_verifier:
            state_id = (data.get('state') or '').strip()
            if state_id:
                entry = _pkce_store.pop(state_id, None)
                if entry and entry['expires_at'] > time.time():
                    code_verifier = entry['code_verifier']
        if not code_verifier:
            code_verifier = request.cookies.get('pkce_code_verifier') or None

        supabase_url_a = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key_a  = current_app.config.get('SUPABASE_SECRET_KEY', '')
        try:
            response = _exchange_code_http(supabase_url_a, service_key_a, code, code_verifier)
        except Exception as e:
            return jsonify({'error': f'Code exchange failed: {str(e)}'}), 401

        user    = response.user
        session = response.session
        if not user or not session:
            return jsonify({'error': 'Failed to exchange code for session'}), 401

        user_metadata = getattr(user, 'user_metadata', {}) or {}
        app_metadata  = getattr(user, 'app_metadata',  {}) or {}
        tenant_id = user_metadata.get('tenant_id') or app_metadata.get('tenant_id')
        role      = user_metadata.get('role')      or app_metadata.get('role') or 'user'

        # Resolve email — Microsoft may return empty email; fall back to preferred_username
        resolved_email = _resolve_azure_email(user, user_metadata)

        bootstrapped = False
        if not tenant_id:
            try:
                tenant_id, role = _bootstrap_azure_tenant(user, user_metadata, app_metadata)
                bootstrapped = True
            except RuntimeError as e:
                return jsonify({'error': str(e)}), 500

        # Refresh session after bootstrap so the new JWT embeds tenant_id in claims
        new_tok = _refresh_session_tokens(session) if bootstrapped else None

        def _tok(field, fallback):
            return (new_tok or {}).get(field) or getattr(session, field, fallback)

        _lazy_pinecone_init(tenant_id)

        def _iso(val):
            if not val:
                return None
            return val.isoformat() if hasattr(val, 'isoformat') else str(val)

        return jsonify({
            'message': 'Microsoft sign-in successful',
            'user': {
                'id':                 user.id,
                'email':              resolved_email,
                'tenant_id':          tenant_id,
                'role':               role,
                'email_confirmed_at': _iso(getattr(user, 'email_confirmed_at', None)),
                'created_at':         _iso(getattr(user, 'created_at', None)),
            },
            'session': {
                'access_token':  _tok('access_token',  session.access_token),
                'refresh_token': _tok('refresh_token', session.refresh_token),
                'expires_at':    _tok('expires_at',    session.expires_at),
                'expires_in':    _tok('expires_in',    session.expires_in),
                'token_type':    _tok('token_type',    session.token_type),
            },
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

            frontend_url = current_app.config.get('FRONTEND_URL', '').rstrip('/')
            return redirect(frontend_url or '/', code=302)
            
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
                frontend_url = current_app.config.get('FRONTEND_URL')
                reset_url = f"{frontend_url}/reset-password/{reset_token}"
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


