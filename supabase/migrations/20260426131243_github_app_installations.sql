create table if not exists github_app_installations (
    installation_id bigint primary key,
    account_id bigint not null,
    account_login text not null,
    account_type text not null,
    html_url text not null,
    target_type text not null,
    permissions jsonb not null default '{}'::jsonb,
    repository_selection text not null,
    setup_action text not null,
    suspended_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists github_app_installations_account_login_idx
    on github_app_installations (account_login);
