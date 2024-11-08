import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";
console.log("\n\n\n/////////////////    verifyUser    /////////////////");
console.log(`[verifyUser]: Function up and running!`);

Deno.serve(async (req: Request) => {
  // Handle CORS preflight request
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  // let isPWMatch = false;
  const userAuth = { Authorized: false, role: "user" };
  try {
    const debug = true;
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      {
        global: {
          headers: { Authorization: req.headers.get("Authorization")! },
        },
      },
    );

    // Parse Request JSON
    const userData = await req.json();

    if (debug) {
      console.log("[verifyUser]: Request data: ", userData);
    }
    // If User exists then verify the PW hash, then return the data.role and Authorized: true
    if (debug) {
      console.log(
        `[verifyUser]: Fetching user data for email: ${userData.email}`,
      );
    }

    // Fetch the user data for the given email
    const { data: users, error: fetchError } = await supabase.from("users")
      .select(
        "*",
      ).eq("email", userData.email);

    // Null check for users
    if (!users || users.length === 0) {
      console.log(`[verifyUser]: Fetch Error: ${fetchError}`);
      return new Response(
        JSON.stringify({ error: "User not found" }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 404,
        },
      );
    }

    // Get the hashed password from the DB
    const hashPW = users[0]["pw_hash"];
    if (debug) {
      console.log(`[verifyUser]: Hash PW for User: ${hashPW}`);
    }

    // Check if the user exists
    if (users && users.length > 0) {
      if (debug) {
        console.log(`[verifyUser]: Got User: ${JSON.stringify(users)}`);
      }
      // Set a var that will be used to check if the password matches
      // const user = users[0];
      // Check if the password matches
      const { data: security, error: saltFetchError } = await supabase
        .from("security").select("*").eq("id", 1);

      // Null check for security
      if (!security || security.length === 0) {
        console.log(`[verifyUser]: Salt Fetch Error: ${saltFetchError}`);
        return new Response(
          JSON.stringify({ error: "Salt not found" }),
          {
            headers: { ...corsHeaders, "Content-Type": "application/json" },
            status: 404,
          },
        );
      }

      // Get the salt from the DB
      const dbSalt = security[0]["salt"];
      if (debug) {
        console.log(`[verifyUser]: Salt from DB: ${dbSalt}`);
      }

      // Hash the user password

      // const hashPW = bcrypt.hashSync(userData.password, dbSalt);
      // console.log(`[verifyUser]: Hash PW Verify for User: ${hashPW}`);
      const serverHashPW = await bcrypt.hash(userData.password, dbSalt);

      if (debug) {
        console.log(`[verifyUser]: User Submitted PW: ${hashPW}`);
        console.log(`[verifyUser]: ServerHashed Val: ${serverHashPW}`);
      }
      if (debug) {
        console.log(
          `[verifyUser]: isPWMatch: ${await bcrypt.compare(
            userData.password,
            hashPW,
          )}`,
        );
      }
    } else {
      console.log(`[verifyUser]: Fetch Error: ${fetchError}`);
      return new Response(
        JSON.stringify({ error: "User not found" }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 404,
        },
      );
    }

    // Return a OK response
    if (debug) {
      console.log(
        `[verifyUser]: Returning response: ${await bcrypt.compare(
          userData.password,
          hashPW,
        )}`,
      );
      console.log(`[verifyUser]: Returning role: ${userAuth.role}`);
    }
    return new Response(
      JSON.stringify({
        authenticated: await bcrypt.compare(userData.password, hashPW),
        role: users[0]["role"],
      }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      },
    );
  } catch (error) {
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 500,
    });
  }
});

// To invoke:
//curl -i --location --request POST 'http://localhost:54321/functions/v1/test' --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU' --header 'Content-Type: application/json' --data '{"name":"Functions"}'
