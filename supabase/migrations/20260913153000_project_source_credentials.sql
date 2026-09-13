alter table faktorial_login_states
    add column if not exists repository_owner text not null default '',
    add column if not exists repository_name text not null default '',
    add column if not exists token_access text not null default '';

create table if not exists faktorial_project_source_credentials (
    credential_hash text primary key,
    github_user_id bigint not null references faktorial_users (github_user_id) on delete cascade,
    project_audience text not null,
    repository_owner text not null check (repository_owner = lower(repository_owner)),
    repository_name text not null check (repository_name = lower(repository_name)),
    token_access text not null check (token_access = 'worker-build'),
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);

alter table faktorial_project_source_credentials enable row level security;
revoke all on faktorial_project_source_credentials from anon, authenticated, public;
