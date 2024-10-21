import { createClient } from "jsr:@supabase/supabase-js@2";

console.log(`[addUser]: Function up and running!`);

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req: Request) => {
  // Handle CORS preflight request
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // Ensure the request is a POST request
    if (req.method !== "POST") {
      return new Response(
        JSON.stringify({ error: "Only POST method is allowed" }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 405, // Method Not Allowed
        },
      );
    }

    // Create a Supabase client with the Auth context of the logged in user
    const _supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      {
        global: {
          headers: { Authorization: req.headers.get("Authorization")! },
        },
      },
    );

    // Parse the incoming JSON request body
    const { fName, lName, email, phone } = await req.json();

    // Check if the required fields are present
    if (!fName || !lName || !email || !phone) {
      return new Response(
        JSON.stringify({ error: "Missing required fields" }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 400, // Bad Request
        },
      );
    }

    // Console.log this
    console.log(`[addUser]: Data Recieved:\n${JSON.stringify({ fName, lName, email, phone })}`);

    // Echo back the user data
    const newUser = { fName, lName, email, phone };

    // You can also add a database insert or other logic here if needed

    return new Response(JSON.stringify(newUser), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });
  } catch (error) {
    // Return an error response
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 400,
    });
  }
});

// To invoke:
//curl -i --location --request POST 'http://localhost:54321/functions/v1/test' --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU' --header 'Content-Type: application/json' --data '{"name":"Functions"}'
