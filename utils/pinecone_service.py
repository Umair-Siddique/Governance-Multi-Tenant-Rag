"""
Pinecone Service for Multi-Tenant Vector Database Management
All tenants share one Pinecone index; each tenant has an isolated namespace.
Strict tenant isolation: operations always use the namespace derived from tenant_id.
"""
from pinecone import Pinecone
from config import Config
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class PineconeService:
    """Service to manage Pinecone namespaces per tenant within a shared index."""

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
        self.shared_index_name = (Config.PINECONE_INDEX_NAME or "").strip()
        if not self.shared_index_name:
            raise ValueError("PINECONE_INDEX_NAME must be set when using Pinecone")

    def _list_index_names(self) -> list:
        existing_indexes = self.pc.list_indexes()
        if hasattr(existing_indexes, "names"):
            return list(existing_indexes.names())
        if isinstance(existing_indexes, list):
            return [idx.name if hasattr(idx, "name") else str(idx) for idx in existing_indexes]
        if hasattr(existing_indexes, "__iter__"):
            return [idx.name if hasattr(idx, "name") else str(idx) for idx in existing_indexes]
        return []

    def shared_index_exists(self) -> bool:
        try:
            return self.shared_index_name in self._list_index_names()
        except Exception as e:
            logger.error("Error checking shared Pinecone index: %s", e)
            return False

    def get_tenant_index_name(self, tenant_id: str) -> str:
        """
        Per-tenant partition id used as the Pinecone namespace (and stored in
        tenants.pinecone_index_name for backward-compatible API/DB shape).
        """
        clean_tenant_id = tenant_id.lower().replace("_", "-")
        return f"tenant-{clean_tenant_id}"

    def get_tenant_namespace(self, tenant_id: str) -> str:
        """Alias for clarity; same value as get_tenant_index_name."""
        return self.get_tenant_index_name(tenant_id)

    def create_tenant_index(self, tenant_id: str, store_in_db: bool = True) -> str:
        """
        Provision vector storage for a tenant: ensure the shared index exists and
        persist the tenant's namespace identifier in the database.

        Args:
            tenant_id: Unique tenant identifier
            store_in_db: If True, stores namespace in tenants.pinecone_index_name

        Returns:
            Namespace string (same shape as legacy per-tenant index names).

        Raises:
            Exception: If the shared index is missing or DB storage fails critically
        """
        namespace = self.get_tenant_namespace(tenant_id)

        if not self.shared_index_exists():
            msg = (
                f"Pinecone index '{self.shared_index_name}' was not found. "
                "Create it in the Pinecone console and set PINECONE_INDEX_NAME if you use a different name."
            )
            logger.error(msg)
            raise Exception(msg)

        logger.info(
            "Tenant %s vector namespace provisioned as '%s' in index '%s'",
            tenant_id,
            namespace,
            self.shared_index_name,
        )

        if store_in_db:
            try:
                self._store_index_name_in_db(tenant_id, namespace)
            except Exception as db_error:
                logger.warning(
                    "Failed to store Pinecone namespace in database for tenant %s: %s",
                    tenant_id,
                    db_error,
                )

        return namespace

    def _store_index_name_in_db(self, tenant_id: str, index_name: str):
        """
        Store the tenant's Pinecone namespace in tenants.pinecone_index_name
        (column name kept for backward compatibility).
        """
        from flask import current_app

        supabase = current_app.supabase_client
        if not supabase:
            raise Exception("Supabase client not available")

        try:
            existing = supabase.table("tenants").select("*").eq("id", tenant_id).execute()

            if existing.data:
                supabase.table("tenants").update(
                    {
                        "pinecone_index_name": index_name,
                        "updated_at": datetime.utcnow().isoformat(),
                    }
                ).eq("id", tenant_id).execute()
            else:
                supabase.table("tenants").insert(
                    {
                        "id": tenant_id,
                        "pinecone_index_name": index_name,
                        "created_at": datetime.utcnow().isoformat(),
                        "updated_at": datetime.utcnow().isoformat(),
                    }
                ).execute()
        except Exception as e:
            logger.error("Failed to store namespace in database for tenant %s: %s", tenant_id, e)
            raise

    def get_index_name_from_db(self, tenant_id: str) -> str:
        """
        Retrieve stored namespace from DB for a tenant (column pinecone_index_name).
        """
        from flask import current_app

        supabase = current_app.supabase_client
        if not supabase:
            return None

        try:
            result = (
                supabase.table("tenants")
                .select("pinecone_index_name")
                .eq("id", tenant_id)
                .execute()
            )

            if result.data and len(result.data) > 0:
                stored = result.data[0].get("pinecone_index_name")
                if stored:
                    expected = self.get_tenant_index_name(tenant_id)
                    if stored == expected:
                        return stored
                    logger.warning(
                        "Stored pinecone_index_name %s does not match expected %s for tenant %s",
                        stored,
                        expected,
                        tenant_id,
                    )
        except Exception as e:
            logger.debug("Could not retrieve namespace from database for tenant %s: %s", tenant_id, e)

        return None

    def index_exists(self, tenant_id: str) -> bool:
        """True if the shared vector index is available (tenant_id kept for API compatibility)."""
        _ = tenant_id
        return self.shared_index_exists()

    def validate_tenant_index_access(self, tenant_id: str, index_name: str) -> bool:
        """
        Validate that index_name is the expected namespace for this tenant.
        """
        expected = self.get_tenant_namespace(tenant_id)

        if index_name != expected:
            logger.error(
                "SECURITY: Tenant %s namespace mismatch (got %s, expected %s)",
                tenant_id,
                index_name,
                expected,
            )
            raise Exception(
                f"Access denied: namespace {index_name} does not belong to tenant {tenant_id}"
            )

        return True

    def get_index(self, tenant_id: str, validate_tenant: bool = True):
        """
        Pinecone Index handle for the shared index. Callers must pass the tenant
        namespace on query/upsert/delete, or use helpers on this service.
        """
        index_name = self.get_tenant_index_name(tenant_id)

        if validate_tenant:
            self.validate_tenant_index_access(tenant_id, index_name)

        if not self.shared_index_exists():
            raise Exception(
                f"Pinecone index '{self.shared_index_name}' does not exist. Create it in the Pinecone console."
            )

        return self.pc.Index(self.shared_index_name)

    def upsert_vectors(self, tenant_id: str, vectors: list[dict]) -> dict:
        """
        Upsert vectors into the tenant's namespace in the shared index.
        """
        self.create_tenant_index(tenant_id, store_in_db=True)
        index = self.get_index(tenant_id)
        namespace = self.get_tenant_namespace(tenant_id)

        if not vectors:
            return {"upserted_count": 0}

        batch_size = 100
        total_upserted = 0
        for i in range(0, len(vectors), batch_size):
            batch = vectors[i : i + batch_size]
            result = index.upsert(vectors=batch, namespace=namespace)
            if hasattr(result, "upserted_count"):
                total_upserted += result.upserted_count or 0
            elif isinstance(result, dict) and "upserted_count" in result:
                total_upserted += result["upserted_count"] or 0

        logger.info(
            "Upserted %s vectors for tenant %s (namespace=%s)",
            len(vectors),
            tenant_id,
            namespace,
        )
        return {"upserted_count": len(vectors)}

    def delete_tenant_index(self, tenant_id: str) -> bool:
        """
        Remove all vectors for the tenant's namespace from the shared index.
        """
        try:
            namespace = self.get_tenant_namespace(tenant_id)
            if not self.shared_index_exists():
                logger.warning(
                    "Shared index %s does not exist; nothing to delete for tenant %s",
                    self.shared_index_name,
                    tenant_id,
                )
                return False

            logger.info(
                "Deleting Pinecone namespace %s for tenant %s in index %s",
                namespace,
                tenant_id,
                self.shared_index_name,
            )
            index = self.pc.Index(self.shared_index_name)
            index.delete(delete_all=True, namespace=namespace)
            return True

        except Exception as e:
            logger.error("Failed to delete Pinecone namespace for tenant %s: %s", tenant_id, e)
            return False
