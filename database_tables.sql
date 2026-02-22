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