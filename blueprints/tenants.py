"""
Tenant profile APIs
Stores tenant onboarding details in the existing tenants table.
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, current_app

from utils.auth_helpers import require_auth


tenants_bp = Blueprint('tenants', __name__)

ALLOWED_TENANT_TYPES = {'self_managed', 'white_label'}


def _default_index_name(tenant_id: str) -> str:
    """Generate a deterministic default index name for tenant storage."""
    clean_tenant_id = tenant_id.lower().replace('_', '-')
    return f"tenant-{clean_tenant_id}"


def _normalize_payload(data: dict):
    """Validate and normalize tenant profile payload."""
    tenant_name = (data.get('tenant_name') or '').strip()
    if not tenant_name:
        return None, "tenant_name is required"

    tenant_type = (data.get('tenant_type') or 'self_managed').strip().lower()
    if tenant_type not in ALLOWED_TENANT_TYPES:
        return None, f"tenant_type must be one of: {sorted(ALLOWED_TENANT_TYPES)}"

    tenant_details = data.get('tenant_details', {})
    if tenant_details is None:
        tenant_details = {}
    if not isinstance(tenant_details, dict):
        return None, "tenant_details must be a JSON object"

    return {
        'tenant_name': tenant_name,
        'tenant_type': tenant_type,
        'tenant_details': tenant_details
    }, None


@tenants_bp.route('/tenants/profile', methods=['POST'])
@require_auth
def upsert_tenant_profile(**kwargs):
    """
    Create or update the authenticated user's tenant profile.
    This endpoint is intended to be called right after account creation/onboarding.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        normalized, error = _normalize_payload(data)
        if error:
            return jsonify({'error': error}), 400

        tenant_id = kwargs.get('tenant_id')
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        existing = supabase.table('tenants').select('*').eq('id', tenant_id).execute()
        existing_row = existing.data[0] if existing.data else None

        pinecone_index_name = None
        if existing_row:
            pinecone_index_name = existing_row.get('pinecone_index_name')
        if not pinecone_index_name:
            pinecone_service = getattr(current_app, 'pinecone_service', None)
            if pinecone_service:
                pinecone_index_name = pinecone_service.get_tenant_index_name(tenant_id)
            else:
                pinecone_index_name = _default_index_name(tenant_id)

        now = datetime.utcnow().isoformat()

        db_payload = {
            'tenant_name': normalized['tenant_name'],
            'tenant_type': normalized['tenant_type'],
            'tenant_details': normalized['tenant_details'],
            'updated_at': now
        }

        if existing_row:
            result = supabase.table('tenants').update(db_payload).eq('id', tenant_id).execute()
            saved = result.data[0] if result.data else None
        else:
            db_payload.update({
                'id': tenant_id,
                'pinecone_index_name': pinecone_index_name,
                'created_at': now
            })
            result = supabase.table('tenants').insert(db_payload).execute()
            saved = result.data[0] if result.data else None

        if not saved:
            return jsonify({'error': 'Failed to save tenant profile'}), 500

        return jsonify({
            'message': 'Tenant profile saved successfully',
            'tenant': {
                'id': saved.get('id'),
                'tenant_name': saved.get('tenant_name'),
                'tenant_type': saved.get('tenant_type'),
                'tenant_details': saved.get('tenant_details') or {},
                'pinecone_index_name': saved.get('pinecone_index_name'),
                'created_at': saved.get('created_at'),
                'updated_at': saved.get('updated_at')
            }
        }), 200
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@tenants_bp.route('/tenants/profile', methods=['GET'])
@require_auth
def get_tenant_profile(**kwargs):
    """Fetch the authenticated user's tenant profile."""
    try:
        tenant_id = kwargs.get('tenant_id')

        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500

        result = supabase.table('tenants').select('*').eq('id', tenant_id).execute()
        if not result.data:
            return jsonify({'error': 'Tenant profile not found'}), 404

        tenant = result.data[0]
        return jsonify({
            'tenant': {
                'id': tenant.get('id'),
                'tenant_name': tenant.get('tenant_name'),
                'tenant_type': tenant.get('tenant_type'),
                'tenant_details': tenant.get('tenant_details') or {},
                'pinecone_index_name': tenant.get('pinecone_index_name'),
                'created_at': tenant.get('created_at'),
                'updated_at': tenant.get('updated_at')
            }
        }), 200
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


