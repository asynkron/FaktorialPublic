create table if not exists faktorial_repository_grants (
    github_user_id bigint not null references faktorial_users (github_user_id) on delete cascade,
    repository_owner text not null check (repository_owner = lower(repository_owner)),
    repository_name text not null check (repository_name = lower(repository_name)),
    token_access text not null check (token_access in ('contents-read', 'legacy')),
    created_at timestamptz not null default now(),
    primary key (github_user_id, repository_owner, repository_name, token_access)
);

alter table faktorial_repository_grants enable row level security;
revoke all on faktorial_repository_grants from anon, authenticated, public;
