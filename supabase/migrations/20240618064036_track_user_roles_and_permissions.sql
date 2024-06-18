-- Ensure the uuid-ossp extension is installed to provide support for UUID generation functions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Custom enum type representing various application permissions
CREATE TYPE public.app_permission AS ENUM ('signs.create', 'signs.update', 'signs.delete', 'signs.read');

-- Custom enum type representing different application roles
CREATE TYPE public.app_role AS ENUM ('go_su', 'go_admin', 'go_staff', 'ds_student');

-- Table to store user roles with a unique identifier for each user-role combination
CREATE TABLE public.user_roles (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Unique identifier for the user role
  user_id UUID REFERENCES public.profiles ON DELETE CASCADE NOT NULL, -- Reference to the user, cascade delete if the user is deleted
  role app_role NOT NULL, -- Role assigned to the user
  UNIQUE (user_id, role) -- Ensures that each user can have only one instance of each role
);
-- Adding a comment to the user_roles table
COMMENT ON TABLE public.user_roles IS 'Application roles for each user.';

-- Enable RLS 
alter table public.user_roles
  enable row level security;

-- Table to store role permissions with a unique identifier for each role-permission combination
CREATE TABLE public.role_permissions (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Unique identifier for the role permission
  role app_role NOT NULL, -- Role that is granted the permission
  permission app_permission NOT NULL, -- Permission granted to the role
  UNIQUE (role, permission) -- Ensures that each role can have only one instance of each permission
);
-- Adding a comment to the role_permissions table
COMMENT ON TABLE public.role_permissions IS 'Application permissions for each role.';

-- Enable RLS
alter table public.role_permissions
  enable row level security;


-- Inserting predefined role-permission mappings into the role_permissions table
INSERT INTO public.role_permissions (role, permission)
VALUES
  ('go_su', 'signs.create'),  -- Superuser role can create signs
  ('go_su', 'signs.read'),    -- Superuser role can read signs
  ('go_su', 'signs.update'),  -- Superuser role can update signs
  ('go_su', 'signs.delete'),  -- Superuser role can delete signs
  ('go_admin', 'signs.create'), -- Admin role can create signs
  ('go_admin', 'signs.read'),   -- Admin role can read signs
  ('go_admin', 'signs.update'), -- Admin role can update signs
  ('go_admin', 'signs.delete'), -- Admin role can delete signs
  ('go_staff', 'signs.create'), -- Staff role can create signs
  ('go_staff', 'signs.read'),   -- Staff role can read signs
  ('go_staff', 'signs.update'), -- Staff role can update signs
  ('go_staff', 'signs.delete'), -- Staff role can delete signs
  ('ds_student', 'signs.read'); -- Student role can only read signs
