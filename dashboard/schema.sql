-- SecretSentinel Supabase Schema Setup

-- 1. Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    scan_mode TEXT NOT NULL DEFAULT 'git',
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    info_count INT NOT NULL DEFAULT 0,
    playbook_content TEXT,
    pr_description_content TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Findings Table (Stores sanitized findings, zero raw secrets)
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    file TEXT NOT NULL,
    start_line INT,
    end_line INT,
    masked_secret TEXT NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'info',
    risk_impact TEXT,
    risk_factors TEXT[] DEFAULT '{}',
    path_type TEXT,
    in_history_only BOOLEAN DEFAULT false,
    verdict TEXT DEFAULT 'needs_review',
    confidence FLOAT DEFAULT 0,
    source TEXT DEFAULT 'heuristic',
    reason TEXT,
    review_status TEXT DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. Enable Row Level Security (RLS)
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

-- 4. RLS Policies for Scans
DROP POLICY IF EXISTS "Users can read all scans" ON public.scans;
CREATE POLICY "Users can read all scans"
    ON public.scans FOR SELECT
    TO authenticated
    USING (true);

DROP POLICY IF EXISTS "Users can insert scans" ON public.scans;
CREATE POLICY "Users can insert scans"
    ON public.scans FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

DROP POLICY IF EXISTS "Users can delete own scans" ON public.scans;
CREATE POLICY "Users can delete own scans"
    ON public.scans FOR DELETE
    TO authenticated
    USING (auth.uid() = user_id OR user_id IS NULL);

-- 5. RLS Policies for Findings
DROP POLICY IF EXISTS "Users can read findings" ON public.findings;
CREATE POLICY "Users can read findings"
    ON public.findings FOR SELECT
    TO authenticated
    USING (true);

DROP POLICY IF EXISTS "Users can insert findings" ON public.findings;
CREATE POLICY "Users can insert findings"
    ON public.findings FOR INSERT
    TO authenticated
    WITH CHECK (true);

DROP POLICY IF EXISTS "Users can update findings review_status" ON public.findings;
CREATE POLICY "Users can update findings review_status"
    ON public.findings FOR UPDATE
    TO authenticated
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS "Users can delete findings" ON public.findings;
CREATE POLICY "Users can delete findings"
    ON public.findings FOR DELETE
    TO authenticated
    USING (true);

