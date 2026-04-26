create table if not exists faktorial_users (
    github_user_id bigint primary key,
    login text not null,
    name text not null default '',
    email text not null default '',
    avatar_url text not null default '',
    html_url text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists faktorial_users_login_idx
    on faktorial_users (lower(login));

create table if not exists faktorial_login_states (
    state text primary key,
    cli_state text not null,
    local_callback_url text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index if not exists faktorial_login_states_expires_at_idx
    on faktorial_login_states (expires_at);

create table if not exists faktorial_sessions (
    token_hash text primary key,
    github_user_id bigint not null references faktorial_users (github_user_id) on delete cascade,
    github_login text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    last_seen_at timestamptz
);

create index if not exists faktorial_sessions_github_user_id_idx
    on faktorial_sessions (github_user_id);

create index if not exists faktorial_sessions_expires_at_idx
    on faktorial_sessions (expires_at);
