"""
Authentication helper utilities
Functions for extracting user and tenant information from JWT tokens
"""
from flask import request, current_app, jsonify
from functools import wraps
from typing import Optional, Tuple


def get_user_from_token() -> Tuple[Optional[dict], Optional[str]]:
    """
    Extract user information from JWT access token
    
    Returns:
        tuple: (user_data, error_message)
        user_data contains: id, email, tenant_id, user_metadata
    """
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return None, "Authorization header is required"
    
    # Extract token (format: "Bearer <token>")
    try:
        token = auth_header.split(' ')[1]
    except IndexError:
        return None, "Invalid authorization header format. Use: Bearer <token>"
    
    # Get Supabase client
    supabase = current_app.supabase_client
    if not supabase:
        return None, "Authentication service not configured"
    
    try:
        # Get user from token using Supabase
        user_response = supabase.auth.get_user(token)
        
        if not user_response or not user_response.user:
            return None, "Invalid or expired token"
        
        user = user_response.user
        
        # Extract tenant_id from user_metadata
        user_metadata = getattr(user, 'user_metadata', {}) or {}
        tenant_id = user_metadata.get('tenant_id')
        
        # If tenant_id not in metadata, try to get from app_metadata
        if not tenant_id:
            app_metadata = getattr(user, 'app_metadata', {}) or {}
            tenant_id = app_metadata.get('tenant_id')
        
        user_data = {
            'id': user.id,
            'email': user.email,
            'tenant_id': tenant_id,
            'user_metadata': user_metadata,
            'app_metadata': getattr(user, 'app_metadata', {}) or {}
        }
        
        return user_data, None
        
    except Exception as e:
        error_msg = str(e)
        lowered = error_msg.lower()
        if 'invalid' in lowered or 'expired' in lowered:
            return None, "Invalid or expired token"
        if 'user from sub claim in jwt does not exist' in lowered:
            return None, "Invalid access token for this project. Use the access_token returned by /auth/signin."
        return None, f"Authentication failed: {error_msg}"


def get_tenant_id_from_token() -> Tuple[Optional[str], Optional[str]]:
    """
    Extract tenant_id from JWT access token
    
    Returns:
        tuple: (tenant_id, error_message)
    """
    user_data, error = get_user_from_token()
    
    if error:
        return None, error
    
    tenant_id = user_data.get('tenant_id')
    
    if not tenant_id:
        return None, "User is not associated with a tenant. Please contact administrator."
    
    return tenant_id, None


def require_auth(f):
    """
    Decorator to require authentication and extract tenant_id from token.
    Adds 'current_user' and 'tenant_id' as keyword arguments to the function.
    tenant_id is automatically extracted from the JWT token.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_data, error = get_user_from_token()

        if error:
            return jsonify({'error': error}), 401

        tenant_id = user_data.get('tenant_id')

        if not tenant_id:
            return jsonify({
                'error': 'User is not associated with a tenant. Please sign out and register again, or contact administrator.'
            }), 403

        # Add user data and tenant_id to kwargs (after route parameters)
        kwargs['current_user'] = user_data
        kwargs['tenant_id'] = tenant_id

        return f(*args, **kwargs)

    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator factory that requires the authenticated user to have one of the
    specified roles (stored in user_metadata.role).

    Allowed roles: 'admin', 'editor', 'reviewer', 'user'

    Usage:
        @require_role('admin')
        def my_view(**kwargs): ...

        @require_role('admin', 'editor')
        def another_view(**kwargs): ...

    Injects 'current_user', 'tenant_id', and 'user_role' into kwargs.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_data, error = get_user_from_token()

            if error:
                return jsonify({'error': error}), 401

            tenant_id = user_data.get('tenant_id')
            if not tenant_id:
                return jsonify({
                    'error': 'User is not associated with a tenant. Please sign out and register again, or contact administrator.'
                }), 403

            # Check role in both user_metadata and app_metadata (app_metadata is in JWT token)
            user_metadata = user_data.get('user_metadata', {}) or {}
            app_metadata = user_data.get('app_metadata', {}) or {}
            user_role = user_metadata.get('role') or app_metadata.get('role') or 'user'

            if user_role not in allowed_roles:
                return jsonify({
                    'error': f'Insufficient permissions. Required role(s): {list(allowed_roles)}. Your role: {user_role}'
                }), 403

            kwargs['current_user'] = user_data
            kwargs['tenant_id'] = tenant_id
            kwargs['user_role'] = user_role

            return f(*args, **kwargs)

        return wrapper
    return decorator

