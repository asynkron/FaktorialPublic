-- Allow a separately granted worker-build capability. Existing grants retain
-- their exact access mode; this migration does not grant it to any user.
alter table faktorial_repository_grants
    drop constraint faktorial_repository_grants_token_access_check;
alter table faktorial_repository_grants
    add constraint faktorial_repository_grants_token_access_check
    check (token_access in ('contents-read', 'legacy', 'worker-build'));
