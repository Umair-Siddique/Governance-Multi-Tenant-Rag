"""
LLM Provider Management API
Handles CRUD operations for tenant LLM provider configurations
All operations are tenant-scoped and require authentication
"""
from flask import Blueprint, request, jsonify, current_app
from utils.encryption_service import EncryptionService
from utils.llm_providers import LLMProviderFactory
from utils.auth_helpers import require_auth
import uuid
from datetime import datetime


llm_providers_bp = Blueprint('llm_providers', __name__)


def get_encryption_service() -> EncryptionService:
    """Get encryption service instance"""
    encryption_key = current_app.config.get('ENCRYPTION_KEY')
    if not encryption_key:
        raise ValueError("ENCRYPTION_KEY not configured")
    return EncryptionService(encryption_key)


def validate_provider_data(data: dict):
    """
    Validate LLM provider data
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    provider_type = data.get('provider_type', '').lower()
    api_key = data.get('api_key', '')
    
    if not provider_type:
        return False, "provider_type is required"
    
    if provider_type not in LLMProviderFactory.get_supported_providers():
        return False, f"Unsupported provider_type. Supported: {LLMProviderFactory.get_supported_providers()}"
    
    if not api_key:
        return False, "api_key is required"
    
    if not api_key.strip():
        return False, "api_key cannot be empty"
    
    return True, ""


@llm_providers_bp.route('/llm-providers', methods=['POST'])
@require_auth
def create_llm_provider(**kwargs):
    """Create a new LLM provider configuration for a tenant"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        # Validate provider data
        is_valid, error_msg = validate_provider_data(data)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        provider_type = data.get('provider_type', '').lower()
        api_key = data.get('api_key', '').strip()
        default_model = data.get('default_model', '')
        is_active = data.get('is_active', True)
        name = data.get('name', f"{provider_type.title()} Provider")
        
        # Encrypt API key
        encryption_service = get_encryption_service()
        encrypted_api_key = encryption_service.encrypt(api_key)
        
        # Validate credentials by creating a test provider instance
        try:
            provider = LLMProviderFactory.create_provider(provider_type, api_key, default_model)
            if not provider.validate_credentials():
                return jsonify({'error': 'Invalid API credentials. Please check your API key.'}), 400
        except Exception as e:
            return jsonify({'error': f'Failed to validate credentials: {str(e)}'}), 400
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # Check if provider already exists for this tenant
        existing = supabase.table('llm_providers').select('*').eq('tenant_id', tenant_id).eq('provider_type', provider_type).execute()
        
        if existing.data:
            # Update existing provider
            provider_id = existing.data[0]['id']
            update_data = {
                'encrypted_api_key': encrypted_api_key,
                'default_model': default_model or None,
                'is_active': is_active,
                'name': name,
                'updated_at': datetime.utcnow().isoformat()
            }
            
            result = supabase.table('llm_providers').update(update_data).eq('id', provider_id).execute()
            
            return jsonify({
                'message': 'LLM provider updated successfully',
                'provider': {
                    'id': provider_id,
                    'tenant_id': tenant_id,
                    'provider_type': provider_type,
                    'name': name,
                    'default_model': default_model or None,
                    'is_active': is_active,
                    'created_at': existing.data[0].get('created_at'),
                    'updated_at': update_data['updated_at']
                }
            }), 200
        
        # Create new provider
        provider_id = str(uuid.uuid4())
        provider_data = {
            'id': provider_id,
            'tenant_id': tenant_id,
            'provider_type': provider_type,
            'name': name,
            'encrypted_api_key': encrypted_api_key,
            'default_model': default_model or None,
            'is_active': is_active,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        result = supabase.table('llm_providers').insert(provider_data).execute()
        
        if not result.data:
            return jsonify({'error': 'Failed to create LLM provider'}), 500
        
        return jsonify({
            'message': 'LLM provider created successfully',
            'provider': {
                'id': provider_id,
                'tenant_id': tenant_id,
                'provider_type': provider_type,
                'name': name,
                'default_model': default_model or None,
                'is_active': is_active,
                'created_at': provider_data['created_at'],
                'updated_at': provider_data['updated_at']
            }
        }), 201
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers', methods=['GET'])
@require_auth
def list_llm_providers(**kwargs):
    """List all LLM providers for a tenant"""
    try:
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # Query providers for tenant
        result = supabase.table('llm_providers').select('*').eq('tenant_id', tenant_id).execute()
        
        # Remove encrypted keys from response
        providers = []
        for provider in result.data:
            providers.append({
                'id': provider.get('id'),
                'tenant_id': provider.get('tenant_id'),
                'provider_type': provider.get('provider_type'),
                'name': provider.get('name'),
                'default_model': provider.get('default_model'),
                'is_active': provider.get('is_active', True),
                'created_at': provider.get('created_at'),
                'updated_at': provider.get('updated_at')
            })
        
        return jsonify({
            'providers': providers,
            'count': len(providers)
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers/<provider_id>', methods=['GET'])
@require_auth
def get_llm_provider(provider_id, **kwargs):
    """Get a specific LLM provider by ID"""
    try:
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # Query provider
        result = supabase.table('llm_providers').select('*').eq('id', provider_id).eq('tenant_id', tenant_id).execute()
        
        if not result.data:
            return jsonify({'error': 'LLM provider not found'}), 404
        
        provider = result.data[0]
        
        # Remove encrypted key from response
        return jsonify({
            'provider': {
                'id': provider.get('id'),
                'tenant_id': provider.get('tenant_id'),
                'provider_type': provider.get('provider_type'),
                'name': provider.get('name'),
                'default_model': provider.get('default_model'),
                'is_active': provider.get('is_active', True),
                'created_at': provider.get('created_at'),
                'updated_at': provider.get('updated_at')
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers/<provider_id>', methods=['PUT'])
@require_auth
def update_llm_provider(provider_id, **kwargs):
    """Update an existing LLM provider"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # Check if provider exists
        existing = supabase.table('llm_providers').select('*').eq('id', provider_id).eq('tenant_id', tenant_id).execute()
        
        if not existing.data:
            return jsonify({'error': 'LLM provider not found'}), 404
        
        # Build update data
        update_data = {
            'updated_at': datetime.utcnow().isoformat()
        }
        
        # Update fields if provided
        if 'name' in data:
            update_data['name'] = data['name']
        
        if 'default_model' in data:
            update_data['default_model'] = data['default_model'] or None
        
        if 'is_active' in data:
            update_data['is_active'] = data['is_active']
        
        # Handle API key update (requires re-encryption and validation)
        if 'api_key' in data:
            api_key = data['api_key'].strip()
            if not api_key:
                return jsonify({'error': 'api_key cannot be empty'}), 400
            
            # Validate credentials
            provider_type = existing.data[0].get('provider_type')
            try:
                provider = LLMProviderFactory.create_provider(provider_type, api_key, update_data.get('default_model'))
                if not provider.validate_credentials():
                    return jsonify({'error': 'Invalid API credentials. Please check your API key.'}), 400
            except Exception as e:
                return jsonify({'error': f'Failed to validate credentials: {str(e)}'}), 400
            
            # Encrypt new API key
            encryption_service = get_encryption_service()
            update_data['encrypted_api_key'] = encryption_service.encrypt(api_key)
        
        # Update provider
        result = supabase.table('llm_providers').update(update_data).eq('id', provider_id).eq('tenant_id', tenant_id).execute()
        
        if not result.data:
            return jsonify({'error': 'Failed to update LLM provider'}), 500
        
        updated_provider = result.data[0]
        
        return jsonify({
            'message': 'LLM provider updated successfully',
            'provider': {
                'id': updated_provider.get('id'),
                'tenant_id': updated_provider.get('tenant_id'),
                'provider_type': updated_provider.get('provider_type'),
                'name': updated_provider.get('name'),
                'default_model': updated_provider.get('default_model'),
                'is_active': updated_provider.get('is_active', True),
                'created_at': updated_provider.get('created_at'),
                'updated_at': updated_provider.get('updated_at')
            }
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers/<provider_id>', methods=['DELETE'])
@require_auth
def delete_llm_provider(provider_id, **kwargs):
    """Delete an LLM provider"""
    try:
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # Check if provider exists
        existing = supabase.table('llm_providers').select('*').eq('id', provider_id).eq('tenant_id', tenant_id).execute()
        
        if not existing.data:
            return jsonify({'error': 'LLM provider not found'}), 404
        
        # Delete provider
        result = supabase.table('llm_providers').delete().eq('id', provider_id).eq('tenant_id', tenant_id).execute()
        
        return jsonify({
            'message': 'LLM provider deleted successfully'
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers/supported', methods=['GET'])
@require_auth
def get_supported_providers(**kwargs):
    """Get list of all supported LLM provider types"""
    try:
        providers = LLMProviderFactory.get_supported_providers()
        
        # Add provider metadata
        provider_info = []
        for provider_type in providers:
            provider_info.append({
                'type': provider_type,
                'name': provider_type.title(),
                'default_models': LLMProviderFactory.get_provider_models(provider_type)
            })
        
        return jsonify({
            'providers': provider_info,
            'count': len(providers)
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers/<provider_type>/models', methods=['GET'])
@require_auth
def get_provider_models(provider_type, **kwargs):
    """Get list of available models for a specific LLM provider type"""
    try:
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        provider_type_lower = provider_type.lower()
        
        # Validate provider type
        if provider_type_lower not in LLMProviderFactory.get_supported_providers():
            return jsonify({
                'error': f'Unsupported provider type: {provider_type}. Supported: {LLMProviderFactory.get_supported_providers()}'
            }), 400
        
        # Try to get API key from tenant's configured provider (optional)
        api_key = None
        supabase = current_app.supabase_client
        if supabase:
            try:
                # Check if tenant has a configured provider of this type
                result = supabase.table('llm_providers').select('*').eq('tenant_id', tenant_id).eq('provider_type', provider_type_lower).eq('is_active', True).limit(1).execute()
                
                if result.data:
                    # Decrypt API key to get real-time model list
                    encryption_service = get_encryption_service()
                    try:
                        api_key = encryption_service.decrypt(result.data[0]['encrypted_api_key'])
                    except Exception:
                        # If decryption fails, continue without API key
                        pass
            except Exception:
                # If database query fails, continue without API key
                pass
        
        # Get models (with or without API key)
        models = LLMProviderFactory.get_provider_models(provider_type_lower, api_key)
        
        return jsonify({
            'provider_type': provider_type_lower,
            'models': models,
            'count': len(models)
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@llm_providers_bp.route('/llm-providers/<provider_id>/test', methods=['POST'])
@require_auth
def test_llm_provider(provider_id, **kwargs):
    """Test LLM provider credentials and connectivity"""
    try:
        # tenant_id is already extracted by @require_auth decorator
        tenant_id = kwargs.get('tenant_id')
        
        # Get Supabase client
        supabase = current_app.supabase_client
        if not supabase:
            return jsonify({'error': 'Database not configured'}), 500
        
        # Get provider
        result = supabase.table('llm_providers').select('*').eq('id', provider_id).eq('tenant_id', tenant_id).execute()
        
        if not result.data:
            return jsonify({'error': 'LLM provider not found'}), 404
        
        provider_data = result.data[0]
        
        # Decrypt API key
        encryption_service = get_encryption_service()
        try:
            api_key = encryption_service.decrypt(provider_data['encrypted_api_key'])
        except Exception as e:
            return jsonify({'error': f'Failed to decrypt API key: {str(e)}'}), 500
        
        # Create provider instance and test
        provider_type = provider_data.get('provider_type')
        default_model = provider_data.get('default_model')
        
        try:
            provider = LLMProviderFactory.create_provider(provider_type, api_key, default_model)
            is_valid = provider.validate_credentials()
            
            if is_valid:
                return jsonify({
                    'message': 'LLM provider credentials are valid',
                    'provider_type': provider_type,
                    'status': 'active'
                }), 200
            else:
                return jsonify({
                    'error': 'LLM provider credentials are invalid',
                    'provider_type': provider_type,
                    'status': 'inactive'
                }), 400
        except Exception as e:
            return jsonify({
                'error': f'Failed to test provider: {str(e)}',
                'provider_type': provider_type,
                'status': 'error'
            }), 400
    
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

