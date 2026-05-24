"""
Public branding endpoint — no authentication required.
Frontend calls this on load to resolve tenant branding by domain or name slug before login.
"""
import re
from flask import Blueprint, request, jsonify, current_app
from flask_cors import cross_origin
from utils.supabase_retry import execute_with_retry

branding_bp = Blueprint('branding', __name__)

BRANDING_FIELDS = [
    'app_name', 'logo_url', 'favicon_url',
    'primary_color', 'secondary_color', 'accent_color',
    'login_background_url', 'support_email', 'footer_text',
]


def _slugify(name: str) -> str:
    """lowercase, spaces → hyphens, strip non-alphanumeric."""
    return re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')


def _build_payload(tenant: dict) -> dict:
    details = tenant.get('tenant_details') or {}
    payload = {
        'tenant_name': tenant.get('tenant_name'),
        'tenant_type': tenant.get('tenant_type'),
        'custom_domain': tenant.get('custom_domain'),
    }
    for field in BRANDING_FIELDS:
        payload[field] = details.get(field)
    return payload


@branding_bp.route('/branding', methods=['GET'])
@cross_origin(origins="*", supports_credentials=False)
def get_branding():
    """
    Resolve tenant branding by:
      ?domain=portal.example.com  — exact match on custom_domain column
      ?name=my-tenant-slug        — slug match against slugify(tenant_name)

    Returns branding object or empty {} (frontend uses platform defaults).
    """
    try:
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({}), 200

        domain = (request.args.get('domain') or '').strip().lower()
        name_slug = (request.args.get('name') or '').strip().lower()

        if not domain and not name_slug:
            return jsonify({}), 200

        tenant = None

        # --- lookup by custom_domain ---
        if domain:
            result = execute_with_retry(
                lambda: supabase
                    .table('tenants')
                    .select('tenant_name, tenant_type, tenant_details, custom_domain')
                    .eq('custom_domain', domain)
                    .limit(1)
                    .execute()
            )
            rows = result.data if result and result.data else []
            if rows:
                tenant = rows[0]

        # --- lookup by name slug ---
        if not tenant and name_slug:
            result = execute_with_retry(
                lambda: supabase
                    .table('tenants')
                    .select('tenant_name, tenant_type, tenant_details, custom_domain')
                    .not_.is_('tenant_name', 'null')
                    .execute()
            )
            rows = result.data if result and result.data else []
            for row in rows:
                if _slugify(row.get('tenant_name') or '') == name_slug:
                    tenant = row
                    break

        if not tenant:
            return jsonify({}), 200

        return jsonify(_build_payload(tenant)), 200

    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
