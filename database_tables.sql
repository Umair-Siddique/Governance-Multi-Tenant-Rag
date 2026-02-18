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

-- Add Row Level Security (RLS) policies for tenant isolation
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

-- Service role can manage all tenants
CREATE POLICY "Service role can manage all tenants"
    ON tenants
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- Authenticated users can only access their own tenant
CREATE POLICY "Users can access their tenant"
    ON tenants
    FOR ALL
    USING (
        auth.role() = 'authenticated' AND
        id::text = (auth.jwt() ->> 'user_metadata')::jsonb->>'tenant_id'
    )
    WITH CHECK (
        auth.role() = 'authenticated' AND
        id::text = (auth.jwt() ->> 'user_metadata')::jsonb->>'tenant_id'
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

-- Add Row Level Security (RLS) policies for tenant isolation
ALTER TABLE llm_providers ENABLE ROW LEVEL SECURITY;

-- Create a policy that allows service_role to bypass RLS
-- Service role (used by backend) can do everything
CREATE POLICY "Service role can manage all LLM providers"
    ON llm_providers
    FOR ALL
    USING (
        auth.role() = 'service_role'
    )
    WITH CHECK (
        auth.role() = 'service_role'
    );

-- Alternative: If you want to keep tenant isolation for regular users
-- but allow service role to bypass, you can use this instead:

-- First, drop the service role policy above if you created it
-- DROP POLICY IF EXISTS "Service role can manage all LLM providers" ON llm_providers;

-- Then create separate policies:
-- 1. Allow service_role full access
CREATE POLICY "Service role full access"
    ON llm_providers
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- 2. For authenticated users (if you want to support direct DB access later)
-- This is optional and can be removed if you only use service role
CREATE POLICY "Users can access their tenant's providers"
    ON llm_providers
    FOR ALL
    USING (
        auth.role() = 'authenticated' AND
        tenant_id::text = (auth.jwt() ->> 'user_metadata')::jsonb->>'tenant_id'
    )
    WITH CHECK (
        auth.role() = 'authenticated' AND
        tenant_id::text = (auth.jwt() ->> 'user_metadata')::jsonb->>'tenant_id'
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

-- Row Level Security
ALTER TABLE tenant_invitations ENABLE ROW LEVEL SECURITY;

-- Service role (backend) has full access
CREATE POLICY "Service role can manage all invitations"
    ON tenant_invitations
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');