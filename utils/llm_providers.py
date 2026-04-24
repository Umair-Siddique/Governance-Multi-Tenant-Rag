"""
LLM Provider Abstraction Layer
Supports multiple LLM providers with a unified interface
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple
import openai
import anthropic
try:
    from mistralai import Mistral
except ImportError:
    Mistral = None  # or handle gracefully


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def generate_completion(self, prompt: str, model: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Generate a completion from the LLM
        
        Args:
            prompt: The input prompt
            model: Optional model name override
            **kwargs: Additional provider-specific parameters
            
        Returns:
            Dictionary with 'content' and 'metadata' keys
        """
        pass
    
    @abstractmethod
    def validate_credentials(self) -> bool:
        """
        Validate that the API credentials are working
        
        Returns:
            True if credentials are valid, False otherwise
        """
        pass
    
    @abstractmethod
    def list_models(self) -> list:
        """
        List all available models for this provider
        
        Returns:
            List of model identifiers (strings)
        """
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider implementation"""
    
    def __init__(self, api_key: str, default_model: str = "gpt-5.2-2025-12-11"):
        """
        Initialize OpenAI provider
        
        Args:
            api_key: OpenAI API key
            default_model: Default model to use (e.g., gpt-5.2-2025-12-11, gpt-5-mini-2025-08-07, gpt-5.2-pro-2025-12-11)
        """
        self.client = openai.OpenAI(api_key=api_key)
        self.default_model = default_model
    
    def generate_completion(self, prompt: str, model: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Generate completion using OpenAI"""
        model_name = model or self.default_model
        
        # Use the new responses.create API
        response = self.client.responses.create(
            model=model_name,
            input=prompt,
            **kwargs
        )
        
        # Extract model name from response if available, otherwise use requested model
        response_model = getattr(response, 'model', model_name)
        
        # Extract usage information if available
        usage_info = {}
        if hasattr(response, 'usage'):
            usage = response.usage
            usage_info = {
                "prompt_tokens": getattr(usage, 'prompt_tokens', 0),
                "completion_tokens": getattr(usage, 'completion_tokens', 0),
                "total_tokens": getattr(usage, 'total_tokens', 0)
            }
        
        return {
            "content": response.output_text,
            "metadata": {
                "model": response_model,
                "usage": usage_info
            }
        }
    
    def validate_credentials(self) -> bool:
        """Validate OpenAI credentials"""
        try:
            # Test with a simple request
            response = self.client.responses.create(
                model=self.default_model,
                input="test"
            )
            return True
        except Exception:
            return False
    
    def list_models(self) -> list:
        """List available OpenAI models"""
        return [
            "gpt-5.2-2025-12-11",
            "gpt-5-mini-2025-08-07",
            "gpt-5.2-pro-2025-12-11"
        ]


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider implementation"""
    
    def __init__(self, api_key: str, default_model: str = "claude-haiku-4-5-20251001"):
        """
        Initialize Anthropic provider
        
        Args:
            api_key: Anthropic API key
            default_model: Default model to use (e.g., claude-haiku-4-5-20251001, claude-sonnet-4-6)
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.default_model = default_model
    
    def generate_completion(self, prompt: str, model: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Generate completion using Anthropic"""
        model_name = model or self.default_model
        
        response = self.client.messages.create(
            model=model_name,
            max_tokens=kwargs.get("max_tokens", 1024),
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return {
            "content": response.content[0].text,
            "metadata": {
                "model": response.model,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens
                }
            }
        }
    
    def validate_credentials(self) -> bool:
        """Validate Anthropic credentials"""
        try:
            self.client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=10,
                messages=[{"role": "user", "content": "test"}]
            )
            return True
        except Exception:
            return False
    
    def list_models(self) -> list:
        """List all available Anthropic models"""
        # Anthropic doesn't have a public models.list() endpoint
        # Return the known available models
        return [
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-6"
        ]


class MistralProvider(LLMProvider):
    """Mistral AI provider implementation"""
    
    def __init__(self, api_key: str, default_model: str = "codestral-latest"):
        """
        Initialize Mistral provider
        
        Args:
            api_key: Mistral API key
            default_model: Default model to use (e.g., codestral-latest, devstral-latest, magistral-medium-latest)
        """
        self.client = Mistral(api_key=api_key)
        self.default_model = default_model
    
    def generate_completion(self, prompt: str, model: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Generate completion using Mistral"""
        model_name = model or self.default_model
        
        # Extract completion_args from kwargs or use defaults
        completion_args = kwargs.get('completion_args', {})
        if 'completion_args' not in kwargs:
            completion_args = {
                "temperature": kwargs.get("temperature", 0.7),
                "max_tokens": kwargs.get("max_tokens", 2048),
                "top_p": kwargs.get("top_p", 1)
            }
        
        # Use the new beta.conversations.start API
        response = self.client.beta.conversations.start(
            inputs=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=model_name,
            instructions=kwargs.get("instructions", ""),
            completion_args=completion_args,
            tools=kwargs.get("tools", [])
        )
        
        # Extract content from response
        # The response structure may vary, so we try multiple possible field names
        content = ""
        # Try common response field names
        for field_name in ['output', 'output_text', 'text', 'content', 'message', 'response']:
            if hasattr(response, field_name):
                field_value = getattr(response, field_name)
                if field_value:
                    if isinstance(field_value, str):
                        content = field_value
                        break
                    elif isinstance(field_value, list) and len(field_value) > 0:
                        if isinstance(field_value[0], dict):
                            content = field_value[0].get('content', field_value[0].get('text', str(field_value[0])))
                        else:
                            content = str(field_value[0])
                        break
        
        # If still no content, try to get it from response dict if it's a dict-like object
        if not content and hasattr(response, '__dict__'):
            for key in ['output', 'output_text', 'text', 'content']:
                if key in response.__dict__:
                    value = response.__dict__[key]
                    if value:
                        content = str(value) if not isinstance(value, str) else value
                        break
        
        # Extract model and usage information
        response_model = getattr(response, 'model', model_name)
        usage_info = {}
        if hasattr(response, 'usage'):
            usage = response.usage
            usage_info = {
                "prompt_tokens": getattr(usage, 'prompt_tokens', getattr(usage, 'input_tokens', 0)),
                "completion_tokens": getattr(usage, 'completion_tokens', getattr(usage, 'output_tokens', 0)),
                "total_tokens": getattr(usage, 'total_tokens', 0)
            }
        
        return {
            "content": content,
            "metadata": {
                "model": response_model,
                "usage": usage_info
            }
        }
    
    def validate_credentials(self) -> bool:
        """Validate Mistral credentials"""
        try:
            # Test with a simple request
            response = self.client.beta.conversations.start(
                inputs=[
                    {
                        "role": "user",
                        "content": "test"
                    }
                ],
                model=self.default_model,
                instructions="",
                completion_args={
                    "temperature": 0.7,
                    "max_tokens": 10,
                    "top_p": 1
                },
                tools=[]
            )
            return True
        except Exception:
            return False
    
    def list_models(self) -> list:
        """List available Mistral models"""
        return [
            "codestral-latest",
            "devstral-latest",
            "devstral-medium-latest",
            "devstral-small-latest",
            "magistral-medium-latest",
            "magistral-small-latest"
        ]


class LLMProviderFactory:
    """Factory for creating LLM provider instances"""
    
    PROVIDERS = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "mistral": MistralProvider
    }
    
    @classmethod
    def create_provider(cls, provider_type: str, api_key: str, default_model: Optional[str] = None) -> LLMProvider:
        """
        Create a provider instance
        
        Args:
            provider_type: One of 'openai', 'anthropic', 'mistral'
            api_key: Decrypted API key
            default_model: Optional default model name
            
        Returns:
            LLMProvider instance
        
        Raises:
            ValueError: If provider type is not supported
        """
        provider_type_lower = provider_type.lower()
        
        if provider_type_lower not in cls.PROVIDERS:
            raise ValueError(f"Unsupported provider type: {provider_type}. Supported: {list(cls.PROVIDERS.keys())}")
        
        provider_class = cls.PROVIDERS[provider_type_lower]
        
        # Set default models if not provided
        if default_model is None:
            defaults = {
                "openai": "gpt-5.2-2025-12-11",
                "anthropic": "claude-haiku-4-5-20251001",
                "mistral": "codestral-latest"
            }
            default_model = defaults.get(provider_type_lower)
        
        return provider_class(api_key, default_model)
    
    @classmethod
    def get_supported_providers(cls) -> list:
        """Get list of supported provider types"""
        return list(cls.PROVIDERS.keys())
    
    @classmethod
    def get_provider_models(cls, provider_type: str, api_key: Optional[str] = None) -> list:
        """
        Get list of available models for a provider type
        
        Args:
            provider_type: One of 'openai', 'anthropic', 'mistral'
            api_key: Optional API key (required for some providers to list models)
            
        Returns:
            List of available model identifiers
            
        Raises:
            ValueError: If provider type is not supported
        """
        provider_type_lower = provider_type.lower()
        
        if provider_type_lower not in cls.PROVIDERS:
            raise ValueError(f"Unsupported provider type: {provider_type}. Supported: {list(cls.PROVIDERS.keys())}")
        
        # For providers that need API key to list models, create a temporary instance
        if api_key:
            try:
                provider = cls.create_provider(provider_type_lower, api_key)
                return provider.list_models()
            except Exception:
                # If API call fails, return default models
                defaults = {
                    "openai": [
                        "gpt-5.2-2025-12-11",
                        "gpt-5-mini-2025-08-07",
                        "gpt-5.2-pro-2025-12-11"
                    ],
                    "anthropic": [
                        "claude-haiku-4-5-20251001",
                        "claude-sonnet-4-6"
                    ],
                    "mistral": [
                        "codestral-latest",
                        "devstral-latest",
                        "devstral-medium-latest",
                        "devstral-small-latest",
                        "magistral-medium-latest",
                        "magistral-small-latest"
                    ]
                }
                return defaults.get(provider_type_lower, [])
        else:
            # Return default models if no API key provided
            defaults = {
                "openai": [
                    "gpt-5.2-2025-12-11",
                    "gpt-5-mini-2025-08-07",
                    "gpt-5.2-pro-2025-12-11"
                ],
                "anthropic": [
                    "claude-haiku-4-5-20251001",
                    "claude-sonnet-4-6"
                ],
                "mistral": [
                    "codestral-latest",
                    "devstral-latest",
                    "devstral-medium-latest",
                    "devstral-small-latest",
                    "magistral-medium-latest",
                    "magistral-small-latest"
                ]
            }
            return defaults.get(provider_type_lower, [])


def resolve_tenant_openai_for_retriever(
    supabase,
    tenant_id: str,
    encryption_service,
) -> Tuple[Optional[Any], str, str, str, Optional[str]]:
    """
    Load the tenant's active OpenAI credentials from ``llm_providers`` for RAG/retriever.

    Embeddings and chat both use OpenAI; the row's ``default_model`` is used for
    filter planning and answer generation when set, otherwise ``Config`` defaults.

    Returns:
        (client, chat_model, filter_model, embedding_model, error_message)
        client is None iff error_message is set.
    """
    from config import Config

    if not supabase:
        return None, "", "", "", "Database not configured"
    if not encryption_service:
        return None, "", "", "", "Encryption service not configured (ENCRYPTION_KEY)"

    try:
        result = (
            supabase.table("llm_providers")
            .select("encrypted_api_key, default_model")
            .eq("tenant_id", tenant_id)
            .eq("provider_type", "openai")
            .eq("is_active", True)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return None, "", "", "", f"Failed to load LLM provider: {e}"

    if not result.data:
        return (
            None,
            "",
            "",
            "",
            "No active OpenAI provider for this tenant. Add one under LLM providers (provider_type openai).",
        )

    row = result.data[0]
    try:
        api_key = encryption_service.decrypt(row["encrypted_api_key"])
    except Exception as e:
        return None, "", "", "", f"Could not decrypt stored API key: {e}"

    if not (api_key or "").strip():
        return None, "", "", "", "OpenAI API key is missing in LLM provider settings"

    default_model = (row.get("default_model") or "").strip()
    chat_model = default_model or Config.RETRIEVER_CHAT_MODEL
    filter_model = default_model or Config.RETRIEVER_FILTER_MODEL
    embedding_model = Config.RETRIEVER_EMBEDDING_MODEL

    try:
        client = openai.OpenAI(api_key=api_key.strip())
    except Exception as e:
        return None, "", "", "", f"Invalid OpenAI client configuration: {e}"

    return client, chat_model, filter_model, embedding_model, None


def resolve_tenant_primary_answer_provider(
    supabase,
    tenant_id: str,
    encryption_service,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    The tenant's active LLM provider row chosen by most recent ``updated_at``.
    Used for the final streamed answer (OpenAI, Anthropic, or Mistral).

    Returns:
        (provider_type, decrypted_api_key, default_model, error_message)
        Any field except error may be None when error_message is set.
    """
    if not supabase:
        return None, None, None, "Database not configured"
    if not encryption_service:
        return None, None, None, "Encryption service not configured (ENCRYPTION_KEY)"

    try:
        result = (
            supabase.table("llm_providers")
            .select("provider_type, encrypted_api_key, default_model, updated_at")
            .eq("tenant_id", tenant_id)
            .eq("is_active", True)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return None, None, None, f"Failed to load LLM provider: {e}"

    if not result.data:
        return None, None, None, "No active LLM provider for this tenant."

    row = result.data[0]
    ptype = (row.get("provider_type") or "").strip().lower()
    try:
        api_key = encryption_service.decrypt(row["encrypted_api_key"])
    except Exception as e:
        return None, None, None, f"Could not decrypt stored API key: {e}"

    if not (api_key or "").strip():
        return None, None, None, "API key is missing in LLM provider settings"

    default_model = (row.get("default_model") or "").strip()
    return ptype, api_key.strip(), default_model, None

