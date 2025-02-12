-- /// INITIAL TABLES ///
create table
  public.tickets (
    id bigint generated by default as identity not null,
    title text not null,
    description text not null,
    user_id uuid not null,
    status text not null default 'pending'::text,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    constraint tickets_pkey primary key (id),
    constraint tickets_user_id_fkey foreign key (user_id) references auth.users (id)
  ) tablespace pg_default;

create table
  public.user_activity_logs (
    id bigint generated by default as identity not null,
    user_id uuid not null,
    activity text not null,
    type text not null,
    timestamp timestamp with time zone not null default now(),
    constraint user_activity_logs_pkey primary key (id),
    constraint user_activity_logs_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
  ) tablespace pg_default;

-- Create a new table to store user keys
create table
  public.user_keys (
    user_id uuid not null,
    two_factor_auth boolean null default false,
    private_key text not null,
    public_key text not null,
    created_at timestamp without time zone null default current_timestamp,
    updated_at timestamp without time zone null default current_timestamp,
    constraint user_keys_pkey primary key (user_id),
    constraint user_keys_user_id_fkey foreign key (user_id) references auth.users (id) on update cascade on delete cascade
  ) tablespace pg_default;

-- Create a new table to store user roles
create table
  public.user_roles (
    user_id uuid not null,
    role text not null,
    constraint user_roles_pkey primary key (user_id),
    constraint user_roles_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
  ) tablespace pg_default;

-- Create a view to map users to their email addresses and two-factor authentication status
create view
  public.user_email_mapping as
select
  u.id as user_id,
  u.email,
  coalesce(uk.two_factor_auth, false) as two_factor_auth
from
  auth.users u
  left join user_keys uk on u.id = uk.user_id;

-- create a view to read the auth.sessions table
create view
  public.sessions as
select
  sessions.id,
  sessions.user_id,
  sessions.created_at,
  sessions.updated_at,
  sessions.factor_id,
  sessions.aal,
  sessions.not_after,
  sessions.refreshed_at,
  sessions.user_agent,
  sessions.ip,
  sessions.tag
from
  auth.sessions;

-- //////
-- NOTE::
-- //////

-- Setup 2 accounts in the Authn section of supabase by logging into supabase studio


-- /// TEST DATA ///

-- Insert dummy data into tickets table
insert into public.tickets (title, description, user_id, status, created_at, updated_at)
values
  ('Issue with login', 'Unable to login with correct credentials', (select id from auth.users where email = 'a@admin.com'), 'pending', now(), now()),
  ('Feature request', 'Add dark mode to the application', (select id from auth.users where email = 'a@user.com'), 'pending', now(), now());

-- Insert dummy data into user_activity_logs table
insert into public.user_activity_logs (user_id, activity, type, timestamp)
values
  ((select id from auth.users where email = 'a@admin.com'), 'Logged in', 'login', now()),
  ((select id from auth.users where email = 'a@user.com'), 'Updated profile', 'update', now());

-- Insert dummy data into user_keys table
insert into public.user_keys (user_id, two_factor_auth, private_key, public_key, created_at, updated_at)
values
  ((select id from auth.users where email = 'a@admin.com'), false, 'private_key_john', 'public_key_john', now(), now()),
  ((select id from auth.users where email = 'a@user.com'), false, 'private_key_jane', 'public_key_jane', now(), now());

-- Insert dummy data into user_roles table
insert into public.user_roles (user_id, role)
values
  ((select id from auth.users where email = 'a@admin.com'), 'user'),
  ((select id from auth.users where email = 'a@user.com'), 'admin');

