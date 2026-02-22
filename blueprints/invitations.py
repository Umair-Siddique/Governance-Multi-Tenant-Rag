import re
import uuid
from datetime import datetime, timedelta, timezone

import requests as http_requests
from flask import Blueprint, request, jsonify, current_app

from utils.auth_helpers import require_role

# Admin CRUD routes  →  registered under /api
invitations_bp = Blueprint('invitations', __name__)

# Public accept-invite routes  →  registered under /auth
invite_accept_bp = Blueprint('invite_accept', __name__)

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
INVITE_EXPIRY_HOURS = 72
INVITABLE_ROLES = {'editor', 'reviewer', 'user'}

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def _validate_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _expires_at() -> str:
    return (_now_utc() + timedelta(hours=INVITE_EXPIRY_HOURS)).isoformat()


def _fmt(dt_value) -> str | None:
    """Safely serialise a datetime or ISO string for JSON responses."""
    if not dt_value:
        return None
    if hasattr(dt_value, 'isoformat'):
        return dt_value.isoformat()
    return str(dt_value)


def _safe_validate_password(password: str):
    """
    Basic password validation (mirrors auth.py rules).
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, None


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN ENDPOINTS  (require role = 'admin')
# ══════════════════════════════════════════════════════════════════════════════

@invitations_bp.route('/invitations', methods=['POST'])
@require_role('admin')
def send_invitation(**kwargs):
    """
    Send an invitation email to a new user.

    Request body:
        {
            "email": "invitee@example.com",
            "role": "editor" | "reviewer" | "user"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        invited_email = (data.get('email') or '').strip().lower()
        role = (data.get('role') or '').strip().lower()

        # ── Validate inputs ──────────────────────────────────────────────────
        if not invited_email:
            return jsonify({'error': 'email is required'}), 400
        if not _validate_email(invited_email):
            return jsonify({'error': 'Invalid email format'}), 400
        if not role:
            return jsonify({'error': 'role is required'}), 400
        if role not in INVITABLE_ROLES:
            return jsonify({'error': f'role must be one of: {sorted(INVITABLE_ROLES)}'}), 400

        tenant_id = kwargs['tenant_id']
        current_user = kwargs['current_user']
        inviter_user_id = current_user['id']
        inviter_email = current_user['email']

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        # ── Guard: no active pending invite for the same email + tenant ──────
        existing_invite = (
            supabase.table('tenant_invitations')
            .select('id, status, expires_at')
            .eq('tenant_id', tenant_id)
            .eq('invited_email', invited_email)
            .eq('status', 'pending')
            .execute()
        )
        if existing_invite.data:
            return jsonify({
                'error': 'A pending invitation already exists for this email address. '
                         'Revoke it first if you want to resend.'
            }), 409

        # ── Resolve tenant name for the email ────────────────────────────────
        tenant_row = supabase.table('tenants').select('tenant_name').eq('id', tenant_id).execute()
        tenant_name = (tenant_row.data[0].get('tenant_name') or 'Your Organisation') if tenant_row.data else 'Your Organisation'

        # ── Create invitation record ─────────────────────────────────────────
        invitation_id = str(uuid.uuid4())
        now = _now_utc().isoformat()
        expires = _expires_at()

        invite_record = {
            'id': invitation_id,
            'tenant_id': tenant_id,
            'invited_email': invited_email,
            'role': role,
            'invited_by': inviter_user_id,
            'status': 'pending',
            'created_at': now,
            'expires_at': expires,
        }
        try:
            result = supabase.table('tenant_invitations').insert(invite_record).execute()
            if not result.data:
                return jsonify({'error': 'Failed to create invitation record'}), 500
        except Exception as db_err:
            err_str = str(db_err).lower()
            if 'duplicate' in err_str or 'unique' in err_str or 'already exists' in err_str:
                return jsonify({
                    'error': 'A pending invitation already exists for this email address. Revoke it first if you want to resend.'
                }), 409
            return jsonify({'error': f'Failed to create invitation: {str(db_err)}'}), 500

        # ── Generate signed token ─────────────────────────────────────────────
        token_service = current_app.token_service
        token_payload = {
            'invitation_id': invitation_id,
            'tenant_id': tenant_id,
            'email': invited_email,
            'role': role,
        }
        invite_token = token_service.generate_invite_token(token_payload)

        # ── Build invite URL (frontend handles the accept UI) ─────────────────
        frontend_url = current_app.config.get('FRONTEND_URL')
        invite_url = f"{frontend_url}/accept-invite/{invite_token}"

        # ── Send invitation email ─────────────────────────────────────────────
        email_service = current_app.email_service
        if not email_service:
            return jsonify({'error': 'Email service not configured'}), 500

        sent = email_service.send_invite_email(
            to_email=invited_email,
            invite_url=invite_url,
            role=role,
            tenant_name=tenant_name,
            inviter_email=inviter_email,
        )
        if not sent:
            # Roll back DB record if email fails
            supabase.table('tenant_invitations').delete().eq('id', invitation_id).execute()
            return jsonify({'error': 'Failed to send invitation email'}), 500

        return jsonify({
            'message': f'Invitation sent to {invited_email}',
            'invitation': {
                'id': invitation_id,
                'tenant_id': tenant_id,
                'invited_email': invited_email,
                'role': role,
                'status': 'pending',
                'invited_by': inviter_user_id,
                'created_at': now,
                'expires_at': expires,
            }
        }), 201

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@invitations_bp.route('/invitations', methods=['GET'])
@require_role('admin')
def list_invitations(**kwargs):
    """
    List all invitations for the authenticated admin's tenant.

    Optional query params:
        ?status=pending|accepted|revoked|expired
    """
    try:
        tenant_id = kwargs['tenant_id']

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        query = (
            supabase.table('tenant_invitations')
            .select('*')
            .eq('tenant_id', tenant_id)
            .order('created_at', desc=True)
        )

        status_filter = request.args.get('status', '').strip().lower()
        if status_filter:
            query = query.eq('status', status_filter)

        result = query.execute()

        invitations = [
            {
                'id': inv.get('id'),
                'tenant_id': inv.get('tenant_id'),
                'invited_email': inv.get('invited_email'),
                'role': inv.get('role'),
                'status': inv.get('status'),
                'invited_by': inv.get('invited_by'),
                'created_at': _fmt(inv.get('created_at')),
                'expires_at': _fmt(inv.get('expires_at')),
                'accepted_at': _fmt(inv.get('accepted_at')),
            }
            for inv in (result.data or [])
        ]

        return jsonify({
            'invitations': invitations,
            'count': len(invitations)
        }), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@invitations_bp.route('/invitations/<invitation_id>', methods=['DELETE'])
@require_role('admin')
def revoke_invitation(invitation_id, **kwargs):
    """
    Revoke a pending invitation.  Only pending invites can be revoked.
    """
    try:
        tenant_id = kwargs['tenant_id']

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        # Fetch and validate ownership
        existing = (
            supabase.table('tenant_invitations')
            .select('*')
            .eq('id', invitation_id)
            .eq('tenant_id', tenant_id)
            .execute()
        )
        if not existing.data:
            return jsonify({'error': 'Invitation not found'}), 404

        invite = existing.data[0]
        if invite['status'] != 'pending':
            return jsonify({
                'error': f"Only pending invitations can be revoked. Current status: {invite['status']}"
            }), 400

        # Mark as revoked (soft delete for audit trail)
        supabase.table('tenant_invitations').update({'status': 'revoked'}).eq('id', invitation_id).execute()

        return jsonify({'message': 'Invitation revoked successfully'}), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENDPOINTS  (no auth required — invitee has no account yet)
# ══════════════════════════════════════════════════════════════════════════════

@invite_accept_bp.route('/accept-invite/<token>', methods=['GET'])
def validate_invite_token(token):
    """
    Validate an invite token and return invitation details.
    Called by the frontend to render the accept-invite form.

    Returns:
        200  { invitation_id, email, role, tenant_name }
        400  { error: "<reason>" }
    """
    try:
        token_service = current_app.token_service
        payload, error = token_service.verify_invite_token(token)
        if error:
            return jsonify({'error': error}), 400

        invitation_id = payload.get('invitation_id')
        tenant_id = payload.get('tenant_id')

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        # Verify invitation still exists and is pending
        inv_result = (
            supabase.table('tenant_invitations')
            .select('*')
            .eq('id', invitation_id)
            .eq('tenant_id', tenant_id)
            .execute()
        )
        if not inv_result.data:
            return jsonify({'error': 'Invitation not found or has been revoked'}), 404

        inv = inv_result.data[0]

        if inv['status'] == 'accepted':
            return jsonify({'error': 'This invitation has already been accepted'}), 400
        if inv['status'] in ('revoked', 'expired'):
            return jsonify({'error': f"This invitation is no longer valid (status: {inv['status']})"}), 400
        if inv['status'] != 'pending':
            return jsonify({'error': 'Invalid invitation status'}), 400

        # Resolve tenant name
        tenant_row = (
            supabase.table('tenants')
            .select('tenant_name')
            .eq('id', tenant_id)
            .execute()
        )
        tenant_name = (tenant_row.data[0].get('tenant_name') or 'Your Organisation') if tenant_row.data else 'Your Organisation'

        return jsonify({
            'invitation': {
                'invitation_id': invitation_id,
                'email': inv['invited_email'],
                'role': inv['role'],
                'tenant_name': tenant_name,
                'expires_at': _fmt(inv.get('expires_at')),
            }
        }), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@invite_accept_bp.route('/accept-invite/<token>', methods=['POST'])
def accept_invite(token):
    """
    Accept an invitation: create the user account and assign role.

    Request body:
        {
            "password": "SecurePass1",
            "full_name": "Jane Doe"   (optional)
        }

    On success the user is created in Supabase with:
        user_metadata.tenant_id  = inviting tenant's id
        user_metadata.role       = invited role
        email_confirm            = True  (invite link = implicit email verification)
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        password = data.get('password', '')
        full_name = (data.get('full_name') or '').strip()

        # ── Validate password ─────────────────────────────────────────────────
        if not password:
            return jsonify({'error': 'password is required'}), 400
        is_valid, pw_error = _safe_validate_password(password)
        if not is_valid:
            return jsonify({'error': pw_error}), 400

        # ── Verify invite token ───────────────────────────────────────────────
        token_service = current_app.token_service
        payload, token_error = token_service.verify_invite_token(token)
        if token_error:
            return jsonify({'error': token_error}), 400

        invitation_id = payload.get('invitation_id')
        tenant_id = payload.get('tenant_id')
        invited_email = payload.get('email')
        role = payload.get('role')

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        # ── Re-check invitation in DB ─────────────────────────────────────────
        inv_result = (
            supabase.table('tenant_invitations')
            .select('*')
            .eq('id', invitation_id)
            .eq('tenant_id', tenant_id)
            .execute()
        )
        if not inv_result.data:
            return jsonify({'error': 'Invitation not found or has been revoked'}), 404

        inv = inv_result.data[0]

        if inv['status'] == 'accepted':
            return jsonify({'error': 'This invitation has already been accepted. Please sign in.'}), 400
        if inv['status'] in ('revoked', 'expired'):
            return jsonify({'error': f"This invitation is no longer valid (status: {inv['status']})"}), 400
        if inv['status'] != 'pending':
            return jsonify({'error': 'Invalid invitation status'}), 400

        # ── Build user metadata ───────────────────────────────────────────────
        user_metadata = {
            'tenant_id': tenant_id,
            'role': role,
        }
        if full_name:
            user_metadata['full_name'] = full_name

        # ── Create Supabase user via direct GoTrue admin REST call ──────────
        # Using http_requests directly avoids the Python client's "user not
        # allowed" restriction that can occur even when email signup is enabled.
        supabase_url = current_app.config.get('SUPABASE_URL', '').rstrip('/')
        service_key  = current_app.config.get('SUPABASE_SECRET_KEY', '')

        create_resp = http_requests.post(
            f"{supabase_url}/auth/v1/admin/users",
            json={
                'email': invited_email,
                'password': password,
                'email_confirm': True,
                'user_metadata': user_metadata,
                'app_metadata': {
                    'provider': 'email',
                    'providers': ['email'],
                    'tenant_id': tenant_id,
                    'role': role,
                },
            },
            headers={
                'Authorization': f'Bearer {service_key}',
                'apikey': service_key,
                'Content-Type': 'application/json',
            },
            timeout=10,
        )

        if create_resp.status_code in (200, 201):
            new_user_data = create_resp.json()
        elif create_resp.status_code == 422:
            try:
                err_msg = create_resp.json().get('message') or create_resp.text
            except Exception:
                err_msg = create_resp.text
            err_lower = err_msg.lower()
            if 'already registered' in err_lower or 'already exists' in err_lower or 'email address already registered' in err_lower:
                return jsonify({'error': 'An account with this email already exists. Please sign in.'}), 409
            return jsonify({'error': f'Failed to create account: {err_msg}'}), 400
        else:
            try:
                err_msg = create_resp.json().get('message') or create_resp.text
            except Exception:
                err_msg = create_resp.text or f'HTTP {create_resp.status_code}'
            return jsonify({'error': f'Failed to create account: {err_msg}'}), 400

        new_user_id    = new_user_data.get('id')
        new_user_email = new_user_data.get('email', invited_email)
        if not new_user_id:
            return jsonify({'error': 'Failed to create user account'}), 500

        # ── Mark invitation as accepted ───────────────────────────────────────
        supabase.table('tenant_invitations').update({
            'status': 'accepted',
            'accepted_at': _now_utc().isoformat(),
        }).eq('id', invitation_id).execute()

        # ── Resolve tenant name for notification email ────────────────────────
        tenant_row = (
            supabase.table('tenants')
            .select('tenant_name')
            .eq('id', tenant_id)
            .execute()
        )
        tenant_name = (
            tenant_row.data[0].get('tenant_name') or 'Your Organisation'
        ) if tenant_row.data else 'Your Organisation'

        # ── Send role-assignment confirmation email ────────────────────────────
        email_service = current_app.email_service
        if email_service:
            email_service.send_role_assignment_email(
                to_email=invited_email,
                role=role,
                tenant_name=tenant_name,
            )

        return jsonify({
            'message': 'Account created successfully. You can now sign in.',
            'user': {
                'id': new_user_id,
                'email': new_user_email,
                'tenant_id': tenant_id,
                'role': role,
            }
        }), 201

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

