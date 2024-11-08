# What is this?

Backend for the dashboard, critical data as well as user logs are maintained here.

- ~~BC atm just stores the DID and serves VC upon successful DID Issues~~
- ~~Forward PII sent from dashboard to the BC~~

  - ~~Use a very basic DB to store PII hashes that were used to generate the DID~~

- ~~Forward VC requests to the BC~~

Supabase edge functions are used to ensure that the dashboard can only request/send data based on the required function being called.

**Nuking edge functions, not worth the time investment**

- Reason:
  - Use of 3rd party cdn libs does not sit right w me
  - Setting up a fastapi server to handle backend tasks, this should not have been this hard
  - Keeping Supabase as a docker container still, just no more edge functions

# Commands to run

```
npm install @supabase/supabase-js
npx supabase init
```

### Install deno via winget (Get the extension as well)

```
winget install DenoLand.Deno
```

### Install Docker Desktop

```
winget install Docker.DockerDesktop
```

### Startup a local supabase instance, Docker desktop is required

- For windows, most likely WSL2, enable the following in Docker Desktop>General
  - "Expose daemon on tcp://localhost:2375 without TLS"
  - "Add the \*.docker.internal names to the host's /etc/hosts file"

```
npx supabase start
```

### Grab the Anon token and check if it matches in the dashboard config, to see the startup page again run

```
npx supabase status
```

### Create the table by running the following SQL Query in the Studio

```
create table
  public."supaChain" (
    id bigint generated by default as identity not null,
    email_hash text not null,
    "fName" text not null,
    "lName" text not null,
    email text not null,
    phone text not null,
    vc text null,
    constraint supachain_pkey primary key (id)
  ) tablespace pg_default;
```

### Deploy the edge functions to the local instance (Not tested yet) by running

```
npx supbase functions deploy

# For testing run this
npx supabase functions serve
```
