-- Custom types
create type public.user_status as enum ('ONLINE', 'OFFLINE');

-- Create the PROFILES table
create table profiles (
  id uuid references auth.users on delete cascade not null primary key, -- Unique identifier referencing the auth.users table with cascade delete
  updated_at timestamp with time zone, -- Timestamp indicating when the profile was last updated
  username text unique, -- Unique username for the profile
  full_name text, -- Full name of the user
  avatar_url text, -- URL to the user's avatar image
  website text, -- URL to the user's personal website
  status user_status default 'OFFLINE'::public.user_status, -- Status of the user, defaulting to 'OFFLINE'

  constraint username_length check (char_length(username) >= 3), -- Ensure username is at least 3 characters long
  CONSTRAINT username_lowercase CHECK (username = lower(username)) -- Ensure username is in lowercase
);

comment on table public.profiles is 'Profile data for each user.'; -- Comment describing the profiles table
comment on column public.profiles.id is 'References the internal Supabase Auth user.'; -- Comment describing the id column

-- Enable row-level security on the profiles table
alter table public.profiles
  enable row level security;

-- Define policies for the profiles table
create policy "Public profiles are viewable by everyone." on public.profiles
  for select using (true); -- Allow everyone to view profiles

create policy "Users can insert their own profile." on public.profiles
  for insert with check ((select auth.uid()) = id); -- Allow users to insert their own profile

create policy "Users can update own profile." on public.profiles
  for update using ((select auth.uid()) = id); -- Allow users to update their own profile

-- Set replica identity to full for the profiles table
alter table public.profiles
  replica identity full;

-- Create a function to handle new user sign-ups
create function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, username, full_name, avatar_url)
  values (new.id, new.raw_user_meta_data->>'username', new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'avatar_url'); -- Insert a new profile

  -- Assign 'ds_student' role to new users
  insert into public.user_roles (user_id, role) values (new.id, 'ds_student');
  return new;
end;
$$ language plpgsql security definer;

-- Create a trigger to execute the handle_new_user function after a new user is created
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Set up a storage bucket for avatars
insert into storage.buckets (id, name)
  values ('avatars', 'avatars');

-- Define access control policies for the storage bucket
create policy "Avatar images are publicly accessible." on storage.objects
  for select using (bucket_id = 'avatars'); -- Allow public access to avatar images

create policy "Anyone can upload an avatar." on storage.objects
  for insert with check (bucket_id = 'avatars'); -- Allow anyone to upload an avatar

-- REALTIME SUBSCRIPTIONS
-- Allow realtime listening only on public tables

begin;
  -- Remove existing realtime publication if any
  drop publication if exists supabase_realtime;

  -- Re-create the publication without enabling it for any tables initially
  create publication supabase_realtime;
commit;

-- Add the profiles table to the realtime publication
alter publication supabase_realtime add table public.profiles;
