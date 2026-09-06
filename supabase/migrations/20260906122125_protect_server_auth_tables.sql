-- These tables are used only by the server's direct Postgres connection.
revoke all on table public.faktorial_users, public.faktorial_sessions,
    public.faktorial_login_states, public.github_app_installations
    from public, anon, authenticated;
alter table public.faktorial_users enable row level security;
alter table public.faktorial_sessions enable row level security;
alter table public.faktorial_login_states enable row level security;
alter table public.github_app_installations enable row level security;
