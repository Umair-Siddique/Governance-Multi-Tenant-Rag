"""
LLM Provider Abstraction Layer
Supports multiple LLM providers with a unified interface
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import openai
import anthropic
from mistralai import Mistral


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


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider implementation"""
    
    def __init__(self, api_key: str, default_model: str = "gpt-4"):
        """
        Initialize OpenAI provider
        
        Args:
            api_key: OpenAI API key
            default_model: Default model to use (e.g., gpt-4, gpt-3.5-turbo)
        """
        self.client = openai.OpenAI(api_key=api_key)
        self.default_model = default_model
    
    def generate_completion(self, prompt: str, model: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Generate completion using OpenAI"""
        model_name = model or self.default_model
        
        response = self.client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "user", "content": prompt}
            ],
            **kwargs
        )
        
        return {
            "content": response.choices[0].message.content,
            "metadata": {
                "model": response.model,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            }
        }
    
    def validate_credentials(self) -> bool:
        """Validate OpenAI credentials"""
        try:
            self.client.models.list()
            return True
        except Exception:
            return False


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider implementation"""
    
    def __init__(self, api_key: str, default_model: str = "claude-3-opus-20240229"):
        """
        Initialize Anthropic provider
        
        Args:
            api_key: Anthropic API key
            default_model: Default model to use (e.g., claude-3-opus-20240229, claude-3-sonnet-20240229)
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
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "test"}]
            )
            return True
        except Exception:
            return False


class MistralProvider(LLMProvider):
    """Mistral AI provider implementation"""
    
    def __init__(self, api_key: str, default_model: str = "mistral-large-latest"):
        """
        Initialize Mistral provider
        
        Args:
            api_key: Mistral API key
            default_model: Default model to use (e.g., mistral-large-latest, mistral-medium-latest)
        """
        self.client = Mistral(api_key=api_key)
        self.default_model = default_model
    
    def generate_completion(self, prompt: str, model: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Generate completion using Mistral"""
        model_name = model or self.default_model
        
        response = self.client.chat.complete(
            model=model_name,
            messages=[
                {"role": "user", "content": prompt}
            ],
            **kwargs
        )
        
        return {
            "content": response.choices[0].message.content,
            "metadata": {
                "model": response.model,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            }
        }
    
    def validate_credentials(self) -> bool:
        """Validate Mistral credentials"""
        try:
            self.client.models.list()
            return True
        except Exception:
            return False


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
                "openai": "gpt-4",
                "anthropic": "claude-3-opus-20240229",
                "mistral": "mistral-large-latest"
            }
            default_model = defaults.get(provider_type_lower)
        
        return provider_class(api_key, default_model)
    
    @classmethod
    def get_supported_providers(cls) -> list:
        """Get list of supported provider types"""
        return list(cls.PROVIDERS.keys())


