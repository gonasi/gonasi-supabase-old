-- Create the auth hook function
create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
as $$
  declare
    claims jsonb;                  -- Declare a variable to hold claims JSON object
    user_role public.app_role;     -- Declare a variable to hold the user role
  begin
    -- Fetch the user role from the user_roles table based on user_id from the event
    select role into user_role from public.user_roles where user_id = (event->>'user_id')::uuid;

    claims := event->'claims';     -- Extract the 'claims' JSON object from the event

    if user_role is not null then
      -- If user_role is found, set the 'user_role' claim in the claims JSON object
      claims := jsonb_set(claims, '{user_role}', to_jsonb(user_role));
    else
      -- If user_role is not found, set the 'user_role' claim to null in the claims JSON object
      claims := jsonb_set(claims, '{user_role}', 'null');
    end if;

    -- Update the 'claims' object in the original event with the modified claims
    event := jsonb_set(event, '{claims}', claims);

    -- Return the modified event
    return event;
  end;
$$;

-- Grant usage on the public schema to the supabase_auth_admin role
grant usage on schema public to supabase_auth_admin;

-- Grant execute permission on the custom_access_token_hook function to supabase_auth_admin role
grant execute
  on function public.custom_access_token_hook
  to supabase_auth_admin;

-- Revoke execute permission on the custom_access_token_hook function from authenticated, anon, and public roles
revoke execute
  on function public.custom_access_token_hook
  from authenticated, anon, public;

-- Grant all permissions on the user_roles table to the supabase_auth_admin role
grant all
  on table public.user_roles
  to supabase_auth_admin;

-- Revoke all permissions on the user_roles table from authenticated, anon, and public roles
revoke all
  on table public.user_roles
  from authenticated, anon, public;

-- Create a policy allowing the supabase_auth_admin role to select (read) from the user_roles table
create policy "Allow auth admin to read user roles" ON public.user_roles
as permissive for select
to supabase_auth_admin
using (true);
