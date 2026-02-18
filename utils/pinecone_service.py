"""
Pinecone Service for Multi-Tenant Vector Database Management
Each tenant has its own isolated Pinecone index
Strict tenant isolation enforced - tenants can only access their own indexes
"""
from pinecone import Pinecone
from pinecone import ServerlessSpec
from config import Config
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class PineconeService:
    """Service to manage Pinecone indexes for tenants"""
    
    def __init__(self, api_key: str = None):
        """
        Initialize Pinecone client
        
        Args:
            api_key: Pinecone API key (defaults to Config.PINECONE_API_KEY)
        """
        self.api_key = api_key or Config.PINECONE_API_KEY
        if not self.api_key:
            raise ValueError("Pinecone API key is required")
        
        self.pc = Pinecone(api_key=self.api_key)
        self.dimension = 1536  # OpenAI embedding dimension
        self.metric = "cosine"
        self.region = "eu-west-1"  # Europe region
        self.cloud = "aws"
    
    def get_tenant_index_name(self, tenant_id: str) -> str:
        """
        Generate index name for a tenant
        
        Args:
            tenant_id: Unique tenant identifier
            
        Returns:
            Index name string
        """
        # Pinecone index names must be lowercase and can contain hyphens
        # Remove any special characters and ensure lowercase
        clean_tenant_id = tenant_id.lower().replace('_', '-')
        return f"tenant-{clean_tenant_id}"
    
    def create_tenant_index(self, tenant_id: str, store_in_db: bool = True) -> str:
        """
        Create a Pinecone index for a tenant if it doesn't exist
        Stores the index name in the database for future reference
        
        Args:
            tenant_id: Unique tenant identifier
            store_in_db: If True, stores index name in database (default: True)
            
        Returns:
            Index name string
            
        Raises:
            Exception: If index creation fails
        """
        index_name = self.get_tenant_index_name(tenant_id)
        
        try:
            # Check if index already exists
            existing_indexes = self.pc.list_indexes()
            # Handle different response formats
            if hasattr(existing_indexes, 'names'):
                existing_names = existing_indexes.names()
            elif isinstance(existing_indexes, list):
                existing_names = [idx.name if hasattr(idx, 'name') else str(idx) for idx in existing_indexes]
            elif hasattr(existing_indexes, '__iter__'):
                existing_names = [idx.name if hasattr(idx, 'name') else str(idx) for idx in existing_indexes]
            else:
                existing_names = []
            
            if index_name in existing_names:
                logger.info(f"Index {index_name} already exists for tenant {tenant_id}")
                # Still store in DB if requested and not already stored
                if store_in_db:
                    try:
                        self._store_index_name_in_db(tenant_id, index_name)
                    except Exception as db_error:
                        logger.warning(f"Failed to store index name in database for tenant {tenant_id}: {str(db_error)}")
                return index_name
            
            # Create new index
            logger.info(f"Creating Pinecone index {index_name} for tenant {tenant_id}")
            
            self.pc.create_index(
                name=index_name,
                dimension=self.dimension,
                metric=self.metric,
                spec=ServerlessSpec(
                    cloud=self.cloud,
                    region=self.region
                )
            )
            
            logger.info(f"Successfully created index {index_name} for tenant {tenant_id}")
            
            # Store index name in database if requested
            if store_in_db:
                try:
                    self._store_index_name_in_db(tenant_id, index_name)
                except Exception as db_error:
                    logger.warning(f"Failed to store index name in database for tenant {tenant_id}: {str(db_error)}")
                    # Don't fail index creation if DB storage fails
            
            return index_name
            
        except Exception as e:
            error_msg = f"Failed to create Pinecone index for tenant {tenant_id}: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    def _store_index_name_in_db(self, tenant_id: str, index_name: str):
        """
        Store Pinecone index name in database for a tenant
        Creates or updates tenant record with index name
        
        Args:
            tenant_id: Unique tenant identifier
            index_name: Pinecone index name
        """
        from flask import current_app
        
        supabase = current_app.supabase_client
        if not supabase:
            raise Exception("Supabase client not available")
        
        # Check if tenant record exists
        try:
            existing = supabase.table('tenants').select('*').eq('id', tenant_id).execute()
            
            if existing.data:
                # Update existing tenant record
                supabase.table('tenants').update({
                    'pinecone_index_name': index_name,
                    'updated_at': datetime.utcnow().isoformat()
                }).eq('id', tenant_id).execute()
            else:
                # Create new tenant record
                supabase.table('tenants').insert({
                    'id': tenant_id,
                    'pinecone_index_name': index_name,
                    'created_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat()
                }).execute()
        except Exception as e:
            logger.error(f"Failed to store index name in database for tenant {tenant_id}: {str(e)}")
            raise
    
    def get_index_name_from_db(self, tenant_id: str) -> str:
        """
        Retrieve Pinecone index name from database for a tenant
        
        Args:
            tenant_id: Unique tenant identifier
            
        Returns:
            Index name string, or None if not found in DB (will generate from tenant_id)
        """
        from flask import current_app
        
        supabase = current_app.supabase_client
        if not supabase:
            return None
        
        try:
            result = supabase.table('tenants').select('pinecone_index_name').eq('id', tenant_id).execute()
            
            if result.data and len(result.data) > 0:
                stored_index_name = result.data[0].get('pinecone_index_name')
                if stored_index_name:
                    # Validate that stored index name matches expected format
                    expected_name = self.get_tenant_index_name(tenant_id)
                    if stored_index_name == expected_name:
                        return stored_index_name
                    else:
                        logger.warning(f"Stored index name {stored_index_name} doesn't match expected {expected_name} for tenant {tenant_id}")
        except Exception as e:
            logger.debug(f"Could not retrieve index name from database for tenant {tenant_id}: {str(e)}")
        
        return None
    
    def index_exists(self, tenant_id: str) -> bool:
        """
        Check if an index exists for a tenant
        
        Args:
            tenant_id: Unique tenant identifier
            
        Returns:
            True if index exists, False otherwise
        """
        try:
            index_name = self.get_tenant_index_name(tenant_id)
            existing_indexes = self.pc.list_indexes()
            # Handle different response formats
            if hasattr(existing_indexes, 'names'):
                existing_names = existing_indexes.names()
            elif isinstance(existing_indexes, list):
                existing_names = [idx.name if hasattr(idx, 'name') else str(idx) for idx in existing_indexes]
            elif hasattr(existing_indexes, '__iter__'):
                existing_names = [idx.name if hasattr(idx, 'name') else str(idx) for idx in existing_indexes]
            else:
                existing_names = []
            return index_name in existing_names
        except Exception as e:
            logger.error(f"Error checking index existence for tenant {tenant_id}: {str(e)}")
            return False
    
    def validate_tenant_index_access(self, tenant_id: str, index_name: str) -> bool:
        """
        Validate that an index name belongs to a specific tenant
        This ensures strict tenant isolation - a tenant can only access their own index
        
        Args:
            tenant_id: Unique tenant identifier
            index_name: Index name to validate
            
        Returns:
            True if index belongs to tenant, False otherwise
            
        Raises:
            Exception: If validation fails
        """
        expected_index_name = self.get_tenant_index_name(tenant_id)
        
        if index_name != expected_index_name:
            logger.error(f"SECURITY: Tenant {tenant_id} attempted to access index {index_name}, but expected {expected_index_name}")
            raise Exception(f"Access denied: Index {index_name} does not belong to tenant {tenant_id}")
        
        return True
    
    def get_index(self, tenant_id: str, validate_tenant: bool = True):
        """
        Get the Pinecone index instance for a tenant with strict tenant validation
        
        Args:
            tenant_id: Unique tenant identifier (must match authenticated tenant)
            validate_tenant: If True, validates tenant_id matches index (default: True)
            
        Returns:
            Pinecone Index instance
            
        Raises:
            Exception: If index doesn't exist or tenant validation fails
        """
        index_name = self.get_tenant_index_name(tenant_id)
        
        # Always validate tenant access
        if validate_tenant:
            self.validate_tenant_index_access(tenant_id, index_name)
        
        if not self.index_exists(tenant_id):
            raise Exception(f"Index {index_name} does not exist for tenant {tenant_id}. Create it first.")
        
        return self.pc.Index(index_name)
    
    def delete_tenant_index(self, tenant_id: str) -> bool:
        """
        Delete a tenant's Pinecone index
        
        Args:
            tenant_id: Unique tenant identifier
            
        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            index_name = self.get_tenant_index_name(tenant_id)
            
            if not self.index_exists(tenant_id):
                logger.warning(f"Index {index_name} does not exist for tenant {tenant_id}")
                return False
            
            logger.info(f"Deleting Pinecone index {index_name} for tenant {tenant_id}")
            self.pc.delete_index(index_name)
            logger.info(f"Successfully deleted index {index_name} for tenant {tenant_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete Pinecone index for tenant {tenant_id}: {str(e)}")
            return False

