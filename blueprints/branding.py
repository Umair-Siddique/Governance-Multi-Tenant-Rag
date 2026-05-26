"""
Public branding endpoint — no authentication required.
Frontend calls this on load to resolve tenant branding by domain or name slug before login.
"""
import re
from flask import Blueprint, request, jsonify, current_app
from flask_cors import cross_origin
from utils.supabase_retry import execute_with_retry
from utils.audit import log_audit_event

branding_bp = Blueprint('branding', __name__)

BRANDING_FIELDS = [
    'app_name', 'logo_url', 'favicon_url',
    'primary_color', 'secondary_color', 'accent_color',
    'login_background_url', 'support_email', 'footer_text',
]

RESERVED_SLUGS = frozenset({'www', 'api', 'admin', 'app', 'auth', 'mail'})

_TENANT_SELECT = 'id, tenant_name, tenant_type, tenant_details, custom_domain'


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


def _lookup_white_label_by_slug(supabase, slug: str) -> dict | None:
    """Find a white_label tenant whose slugify(tenant_name) equals slug."""
    result = execute_with_retry(
        lambda: supabase
            .table('tenants')
            .select(_TENANT_SELECT)
            .eq('tenant_type', 'white_label')
            .not_.is_('tenant_name', 'null')
            .execute()
    )
    rows = result.data if result and result.data else []
    for row in rows:
        if _slugify(row.get('tenant_name') or '') == slug:
            return row
    return None


@branding_bp.route('/branding', methods=['GET'])
@cross_origin(origins="*", supports_credentials=False)
def get_branding():
    """
    Resolve tenant branding by:
      ?domain=<slug>.elorag.com    — white-label subdomain (slug matched against white_label tenants)
      ?domain=portal.example.com  — exact match on custom_domain column (vanity domain)
      ?name=my-tenant-slug        — slug match against slugify(tenant_name) (dev parity)

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

        root_domain = current_app.config.get('ROOT_DOMAIN', 'elorag.com')
        subdomain_suffix = f'.{root_domain}'

        tenant = None

        if domain:
            # --- white-label subdomain: <slug>.elorag.com ---
            if domain.endswith(subdomain_suffix):
                slug = domain[: -len(subdomain_suffix)]
                if slug and slug not in RESERVED_SLUGS:
                    tenant = _lookup_white_label_by_slug(supabase, slug)
                    if tenant:
                        log_audit_event(
                            tenant_id=tenant['id'],
                            event_category='admin',
                            event_type='admin.white_label_portal_access',
                            metadata={'hostname': domain, 'resolved_slug': slug},
                            ip_address=request.remote_addr,
                        )

            # --- vanity custom domain: exact match ---
            if not tenant:
                result = execute_with_retry(
                    lambda: supabase
                        .table('tenants')
                        .select(_TENANT_SELECT)
                        .eq('custom_domain', domain)
                        .limit(1)
                        .execute()
                )
                rows = result.data if result and result.data else []
                if rows:
                    tenant = rows[0]

        # --- lookup by name slug (dev parity / explicit slug query) ---
        if not tenant and name_slug:
            result = execute_with_retry(
                lambda: supabase
                    .table('tenants')
                    .select(_TENANT_SELECT)
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
