-- Tenants table to store tenant information and Pinecone index names
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    pinecone_index_name VARCHAR(255) NOT NULL UNIQUE,
    tenant_name VARCHAR(255),
    tenant_type VARCHAR(50) DEFAULT 'self_managed' CHECK (tenant_type IN ('self_managed', 'white_label')),
    tenant_details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Safe migration block for existing environments
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS tenant_details JSONB DEFAULT '{}'::jsonb;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_tenant_type_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_tenant_type_check CHECK (tenant_type IN ('self_managed', 'white_label'));

-- Enable RLS
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

-- Drop old policies before recreating
DROP POLICY IF EXISTS "Service role can manage all tenants" ON tenants;
DROP POLICY IF EXISTS "Users can access their tenant" ON tenants;

-- Any authenticated user can only read/write their own tenant row.
-- tenant_id is stored under user_metadata.tenant_id in the JWT.
-- auth.jwt()->'user_metadata'->>'tenant_id' correctly parses the nested JSON.
CREATE POLICY "Tenant isolation for authenticated users"
    ON tenants
    FOR ALL
    TO authenticated
    USING (
        id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );

CREATE TABLE llm_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    provider_type VARCHAR(50) NOT NULL CHECK (provider_type IN ('openai', 'anthropic', 'mistral')),
    name VARCHAR(255) NOT NULL,
    encrypted_api_key TEXT NOT NULL,
    default_model VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, provider_type),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Enable RLS
ALTER TABLE llm_providers ENABLE ROW LEVEL SECURITY;

-- Drop old policies before recreating
DROP POLICY IF EXISTS "Service role can manage all LLM providers" ON llm_providers;
DROP POLICY IF EXISTS "Service role full access" ON llm_providers;
DROP POLICY IF EXISTS "Users can access their tenant's providers" ON llm_providers;

-- Any authenticated user can only read/write rows belonging to their own tenant.
CREATE POLICY "Tenant isolation for authenticated users"
    ON llm_providers
    FOR ALL
    TO authenticated
    USING (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );

-- ============================================================
-- Tenant Invitations
-- Stores pending / accepted / revoked invites sent by admins
-- ============================================================
CREATE TABLE IF NOT EXISTS tenant_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    invited_email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('editor', 'reviewer', 'user')),
    invited_by UUID NOT NULL,       -- user_id (UUID) of the admin who sent the invite
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Prevent duplicate active invites for the same email inside the same tenant
CREATE UNIQUE INDEX IF NOT EXISTS tenant_invitations_pending_unique
    ON tenant_invitations (tenant_id, invited_email)
    WHERE status = 'pending';

-- Enable RLS
ALTER TABLE tenant_invitations ENABLE ROW LEVEL SECURITY;

-- Drop old policies before recreating
DROP POLICY IF EXISTS "Service role can manage all invitations" ON tenant_invitations;

-- Any authenticated user can only read/write invitations belonging to their own tenant.
CREATE POLICY "Tenant isolation for authenticated users"
    ON tenant_invitations
    FOR ALL
    TO authenticated
    USING (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );

-- ============================================================
-- Documents (CMS content with Draft → Review → Approved lifecycle)
-- ============================================================
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    filename VARCHAR(500) NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('pending_processing', 'draft', 'review', 'approved', 'processing_failed', 'rejected')),
    uploaded_by UUID NOT NULL,
    raw_text TEXT,
    chunk_count INTEGER DEFAULT 0,
    storage_path VARCHAR(1000),
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS documents_tenant_status_idx ON documents (tenant_id, status);
CREATE INDEX IF NOT EXISTS documents_pending_processing_idx ON documents (tenant_id, status) 
    WHERE status = 'pending_processing';
CREATE INDEX IF NOT EXISTS documents_rejected_idx ON documents (tenant_id, status)
    WHERE status = 'rejected';

-- Safe migration for existing environments
ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN ('pending_processing', 'draft', 'review', 'approved', 'processing_failed', 'rejected'));
ALTER TABLE documents ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- Enable RLS
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Tenant isolation for documents" ON documents;
CREATE POLICY "Tenant isolation for documents"
    ON documents
    FOR ALL
    TO authenticated
    USING (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );

-- ============================================================
-- Document Chunks (for reviewer to view all chunks before approval)
-- ============================================================
CREATE TABLE IF NOT EXISTS document_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    char_count INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(document_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS document_chunks_document_idx ON document_chunks (document_id);
CREATE INDEX IF NOT EXISTS document_chunks_tenant_idx ON document_chunks (tenant_id);

-- Enable RLS
ALTER TABLE document_chunks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Tenant isolation for document_chunks" ON document_chunks;
CREATE POLICY "Tenant isolation for document_chunks"
    ON document_chunks
    FOR ALL
    TO authenticated
    USING (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );

-- ============================================================
-- CSV Registry (Metadata Catalog for CSV files)
-- Stores file metadata and LLM-generated summary; no raw rows.
-- Bridges with Pinecone via file_id in vector metadata.
-- ============================================================
CREATE TABLE IF NOT EXISTS csv_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    filename VARCHAR(500) NOT NULL,
    columns JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('pending_processing', 'draft', 'review', 'approved', 'processing_failed', 'rejected')),
    uploaded_by UUID NOT NULL,
    row_count INTEGER DEFAULT 0,
    chunk_count INTEGER DEFAULT 0,
    storage_path VARCHAR(1000),
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS csv_registry_tenant_status_idx ON csv_registry (tenant_id, status);
CREATE INDEX IF NOT EXISTS csv_registry_pending_processing_idx ON csv_registry (tenant_id, status) 
    WHERE status = 'pending_processing';
CREATE INDEX IF NOT EXISTS csv_registry_rejected_idx ON csv_registry (tenant_id, status)
    WHERE status = 'rejected';

-- Safe migration for existing environments
ALTER TABLE csv_registry DROP CONSTRAINT IF EXISTS csv_registry_status_check;
ALTER TABLE csv_registry ADD CONSTRAINT csv_registry_status_check
    CHECK (status IN ('pending_processing', 'draft', 'review', 'approved', 'processing_failed', 'rejected'));
ALTER TABLE csv_registry ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

ALTER TABLE csv_registry ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Tenant isolation for csv_registry" ON csv_registry;
CREATE POLICY "Tenant isolation for csv_registry"
    ON csv_registry
    FOR ALL
    TO authenticated
    USING (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );

-- ============================================================
-- CSV Chunks (row-group text for embedding; links to Pinecone)
-- Each chunk = searchable text for a group of rows (for embedding).
-- ============================================================
CREATE TABLE IF NOT EXISTS csv_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    csv_file_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    char_count INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (csv_file_id) REFERENCES csv_registry(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(csv_file_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS csv_chunks_csv_file_idx ON csv_chunks (csv_file_id);
CREATE INDEX IF NOT EXISTS csv_chunks_tenant_idx ON csv_chunks (tenant_id);

ALTER TABLE csv_chunks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Tenant isolation for csv_chunks" ON csv_chunks;
CREATE POLICY "Tenant isolation for csv_chunks"
    ON csv_chunks
    FOR ALL
    TO authenticated
    USING (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    )
    WITH CHECK (
        tenant_id::text = (auth.jwt()->'user_metadata'->>'tenant_id')
    );