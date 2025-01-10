# What is this?

Backend for the dashboard, critical data as well as user logs are maintained here.

- ~~BC atm just stores the DID and serves VC upon successful DID Issues~~
- ~~Forward PII sent from dashboard to the BC~~

  - ~~Use a very basic DB to store PII hashes that were used to generate the DID~~
- ~~Forward VC requests to the BC~~

~~Supabase edge functions are used to ensure that the dashboard can only request/send data based on the required function being called.~~

**Nuking edge functions, not worth the time investment**

- Reason:
  - Use of 3rd party cdn libs does not sit right w me
  - Setting up a fastapi server to handle backend tasks, this should not have been this hard
  - Keeping Supabase as a docker container still, just no more edge functions

# Commands to run

### Install Python

Do not use versions above 3.12.8

### Git Clone the repo

```
git clone http://github.com/blackgateproject/backend
```

### Start the connector server

```
# Using a venv is recommended, but not required
# python -m venv .venv

pip install -r requirements.txt

# pip install fastapi[standard] supabase didkit web3 sqlmodel pydantic_settings eth_keys eth_utils requests

fastapi run dev
```

### Install Docker Desktop

```
winget install Docker.DockerDesktop
```

### Startup a local supabase instance, Docker desktop is required

- For windows, most likely WSL2, enable the following in Docker Desktop>General
  - "Expose daemon on tcp://localhost:2375 without TLS"
  - "Add the \*.docker.internal names to the host's /etc/hosts file"

### Head to /supabase dir in the repo and deploy the backend

```
cd supabase/supabase
npm i
npx supabase start
```

### Grab the Anon token and check if it matches in the dashboard config, to see the startup page again run

```
npx supabase status
```

### Create the table by running the tableDef.sql query in the SQL Editior in supabase studio

### Update the .env file in /app to contain the newly generated anon and serv keys

### Setup IFPS

```
docker pull ipfs/kubo
```
