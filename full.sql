-- Ensure the uuid-ossp extension is installed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Custom types
create type public.app_permission as enum ('signs.create', 'signs.update', 'signs.delete', 'signs.read');
create type public.app_role as enum ('go_su', 'go_admin', 'go_staff', 'ds_student');
create type public.road_signs_classes as enum ('Class A', 'Class B', 'Class C', 'Class D');
create type public.road_signs_class_names as enum ('Regulatory Signs', 'Warning Signs', 'Traffic Lights Signals', 'Carriageway Markings and Kerb Markings');
create type public.user_status as enum ('ONLINE', 'OFFLINE');

-- PROFILES
create table profiles (
  id uuid references auth.users on delete cascade not null primary key,
  updated_at timestamp with time zone,
  username text unique,
  full_name text,
  avatar_url text,
  website text,
  status user_status default 'OFFLINE'::public.user_status

  constraint username_length check (char_length(username) >= 3)
  CONSTRAINT username_lowercase CHECK (username = lower(username))
);

comment on table public.profiles is 'Profile data for each user.';
comment on column public.profiles.id is 'References the internal Supabase Auth user.';

-- ROAD SIGNS CATEGORIES
create table public.road_signs_categories (
  id uuid default uuid_generate_v4() primary key,
  sign_class_name road_signs_classes not null,
  category_name road_signs_class_names not null,
  description text,
  inserted_at timestamp with time zone default timezone('utc'::text, now()) not null,
  created_by uuid references public.profiles not null
);
comment on table public.road_signs_categories is 'Road Signs Categories';
comment on column public.road_signs_categories.sign_class_name is 'Road signs categories (A, B, C, D)';
comment on column public.road_signs_categories.category_name is 'Regulatory signs, Warnig Signs etc.';


-- ROAD SIGNS
create table public.road_signs (
  id uuid default uuid_generate_v4() primary key,
  name text not null,
  description text,
  category uuid references public.road_signs_categories not null,
  sign_url text,
  inserted_at timestamp with time zone default timezone('utc'::text, now()) not null,
  created_by uuid references public.profiles not null
);
comment on table public.road_signs is 'All Road Signs';
comment on column public.road_signs.sign_url is 'URL of 3D asset';

-- USER ROLES
create table public.user_roles (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references public.profiles on delete cascade not null,
  role app_role not null,
  unique (user_id, role)
);
comment on table public.user_roles is 'Application roles for each user.';

-- ROLE PERMISSIONS
create table public.role_permissions (
  id uuid default uuid_generate_v4() primary key,
  role app_role not null,
  permission app_permission not null,
  unique (role, permission)
);
comment on table public.role_permissions is 'Application permissions for each role.';

-- authorize with role-based access control (RBAC)
create function public.authorize(
  requested_permission app_permission,
  user_id uuid
)
returns boolean as
$$
  declare
    bind_permissions int;
  begin
    select
      count(*)
    from public.role_permissions
    inner join public.user_roles on role_permissions.role = user_roles.role
    where
      role_permissions.permission = authorize.requested_permission and
      user_roles.user_id = authorize.user_id
    into bind_permissions;

    return bind_permissions > 0;
  end;
$$
language plpgsql security definer;

-- Secure the tables
alter table public.profiles
  enable row level security;
alter table public.road_signs_categories
  enable row level security;
alter table public.road_signs
  enable row level security;
alter table public.user_roles
  enable row level security;
alter table public.role_permissions
  enable row level security;

-- profiles
create policy "Public profiles are viewable by everyone." on public.profiles
  for select using (true); -- allow username check hence public
create policy "Users can insert their own profile." on public.profiles
  for insert with check ((select auth.uid()) = id);
create policy "Users can update own profile." on public.profiles
  for update using ((select auth.uid()) = id);

-- road_signs_categories
create policy "Allow logged-in read access to signs categories" on public.road_signs_categories
  for select using (auth.role() = 'authenticated');
create policy "Allow authorized create access" on public.road_signs_categories
  for insert with check (authorize('signs.create', auth.uid()));
create policy "Allow authorized update access" on public.road_signs_categories
  for update using (authorize('signs.update', auth.uid()));
create policy "Allow authorized delete access" on public.road_signs_categories
  for delete using (authorize('signs.delete', auth.uid()));

-- road_signs
create policy "Allow logged-in read access to signs" on public.road_signs
  for select using (auth.role() = 'authenticated');
create policy "Allow authorized create access" on public.road_signs
  for insert with check (authorize('signs.create', auth.uid()));
create policy "Allow authorized update access" on public.road_signs
  for update using (authorize('signs.update', auth.uid()));
create policy "Allow authorized delete access" on public.road_signs
  for delete using (authorize('signs.delete', auth.uid()));

-- user_roles
create policy "Allow individual read access" on public.user_roles
  for select using ((select auth.uid()) = user_id);

-- Send "previous data" on change
alter table public.profiles
  replica identity full;
alter table public.road_signs_categories
  replica identity full;
alter table public.road_signs
  replica identity full;



-- This trigger automatically creates a profile entry when a new user signs up via Supabase Auth.
-- See https://supabase.com/docs/guides/auth/managing-user-data#using-triggers for more details.
create function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, username, full_name, avatar_url)
  values (new.id, new.raw_user_meta_data->>'username', new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'avatar_url');

  -- ds_student as default role when new user signs up
  insert into public.user_roles (user_id, role) values (new.id, 'ds_student');
  return new;
end;
$$ language plpgsql security definer;


-- trigger the function every time a user is created
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Set up Storage!
insert into storage.buckets (id, name)
  values ('avatars', 'avatars');

-- Set up access controls for storage.
-- See https://supabase.com/docs/guides/storage#policy-examples for more details.
create policy "Avatar images are publicly accessible." on storage.objects
  for select using (bucket_id = 'avatars');

create policy "Anyone can upload an avatar." on storage.objects
  for insert with check (bucket_id = 'avatars');



/**
 * REALTIME SUBSCRIPTIONS
 * Only allow realtime listening on public tables.
 */

begin;
  -- remove the realtime publication
  drop publication if exists supabase_realtime;

  -- re-create the publication but don't enable it for any tables
  create publication supabase_realtime;
commit;

-- add tables to the publication
alter publication supabase_realtime add table public.profiles;


insert into public.role_permissions (role, permission)
values
  ('go_su', 'signs.create'),
  ('go_su', 'signs.read'),
  ('go_su', 'signs.update'),
  ('go_su', 'signs.delete'),
  ('go_admin', 'signs.create'),
  ('go_admin', 'signs.read'),
  ('go_admin', 'signs.update'),
  ('go_admin', 'signs.delete'),
  ('go_staff', 'signs.create'),
  ('go_staff', 'signs.read'),
  ('go_staff', 'signs.update'),
  ('go_staff', 'signs.delete'),
  ('ds_student', 'signs.read');