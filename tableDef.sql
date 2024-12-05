create table
  public.users (
    id bigint generated by default as identity not null,
    first_name text not null default ''::text,
    second_name text not null default ''::text,
    pw_hash text not null default ''::text,
    email text not null default ''::text,
    phone_number text null,
    created_at timestamp with time zone not null default now(),
    last_access_at timestamp with time zone null,
    role text not null default 'user'::text,
    constraint users_pkey primary key (id),
    constraint users_email_key unique (email),
    constraint users_phone_number_key unique (phone_number),
    constraint users_role_key unique (role)
  ) tablespace pg_default;

-- Drop the existing tickets table if it exists
drop table if exists public.tickets;

-- Recreate the tickets table with UUID user_id
create table
  public.tickets (
    id bigint generated by default as identity not null,
    title text not null,
    description text not null,
    user_id uuid not null references auth.users(id), -- Changed to UUID and referencing auth.users
    status text not null default 'pending'::text,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    constraint tickets_pkey primary key (id)
  ) tablespace pg_default;

-- Create a new table to map users to their roles
create table public.user_roles (
    user_id uuid references auth.users(id) on delete cascade,
    role text not null,
    constraint user_roles_pkey primary key (user_id)
) tablespace pg_default;

-- Create a new table to log user activities
create table public.user_activity_logs (
    id bigint generated by default as identity not null,
    user_id uuid not null references auth.users(id) on delete cascade,
    activity text not null,
    type text not null, -- New field for type
    timestamp timestamp with time zone not null default now(),
    constraint user_activity_logs_pkey primary key (id)
) tablespace pg_default;
