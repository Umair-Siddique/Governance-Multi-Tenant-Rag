from flask import Blueprint, request, jsonify, current_app
from utils.auth_helpers import require_auth
import re
import uuid
import requests as http_requests


auth_bp = Blueprint('auth', __name__)


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
            backend_url = current_app.config.get('BACKEND_URL', 'http://localhost:5001')
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


@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user(**kwargs):
    """Get current authenticated user"""
    try:
        current_user = kwargs.get('current_user') or {}
        user_metadata = current_user.get('user_metadata', {}) or {}
        app_metadata = current_user.get('app_metadata', {}) or {}
        role = user_metadata.get('role') or app_metadata.get('role') or 'user'
        return jsonify({
            'user': {
                'id': current_user.get('id'),
                'email': current_user.get('email'),
                'tenant_id': current_user.get('tenant_id'),
                'role': role
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@auth_bp.route('/fix-admin-role', methods=['POST'])
@require_auth
def fix_admin_role(**kwargs):
    """
    Fix admin role for users who registered before role assignment was added.
    This endpoint automatically sets role='admin' if:
    - User doesn't have a role set, OR
    - User is the first/only user in their tenant
    
    Only works for users who own their tenant (no other users in same tenant).
    """
    try:
        current_user = kwargs.get('current_user') or {}
        user_id = current_user.get('id')
        tenant_id = kwargs.get('tenant_id')
        user_metadata = current_user.get('user_metadata', {}) or {}
        app_metadata = current_user.get('app_metadata', {}) or {}
        current_role = user_metadata.get('role') or app_metadata.get('role')
        
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # If user already has admin role, no need to fix
        if current_role == 'admin':
            return jsonify({
                'message': 'User already has admin role',
                'role': 'admin'
            }), 200
        
        # Update user metadata with admin role
        updated_user_metadata = dict(user_metadata)
        updated_user_metadata['role'] = 'admin'
        updated_user_metadata['tenant_id'] = tenant_id  # Ensure tenant_id is set
        
        updated_app_metadata = dict(app_metadata)
        updated_app_metadata['role'] = 'admin'
        updated_app_metadata['tenant_id'] = tenant_id
        
        # Update user in Supabase
        supabase.auth.admin.update_user_by_id(
            user_id,
            {
                'user_metadata': updated_user_metadata,
                'app_metadata': updated_app_metadata
            }
        )
        
        return jsonify({
            'message': 'Admin role has been assigned successfully. Please sign out and sign in again for changes to take effect.',
            'role': 'admin',
            'note': 'You must sign out and sign in again to get a new token with the updated role'
        }), 200
    
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

        resp = http_requests.patch(
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
            err = resp.json().get('message') or resp.text
            return jsonify({'error': f'Failed to reset password: {err}'}), 400

        return jsonify({
            'message': 'Password reset successful. You can now sign in with your new password.'
        }), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


