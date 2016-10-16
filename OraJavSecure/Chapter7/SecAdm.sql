-- Chapter7/SecAdm.sql
-- Copyright 2011, David Coffin

-- Connect as our Security Administrator user
--CONNECT secadm;

-- Always execute procedure to acquire Security Administrator role
EXECUTE sys.p_check_secadm_access;

-- We need a place and space to insert data associated with APPSEC
ALTER USER appsec DEFAULT TABLESPACE USERS QUOTA 2M ON USERS;

GRANT CREATE TRIGGER TO appsec_role;

-- There are times when you cannot grant execute to a role and succeed
-- This instance has a package in the HR schema that executes a package
-- in the AppSec schema.  If we grant execute of AppSec package to a role
-- and grant the role to HR (as a default role), things should work, right?
-- Role for privileges required by Application Security user
--CREATE ROLE appsec_user_role NOT IDENTIFIED;
-- Give permission for Applications to execute Application Security package
--GRANT EXECUTE ON appsec.app_sec_pkg TO appsec_user_role;
-- Grant the role to HR Application schema -- becomes a default role
--GRANT appsec_user_role TO hr;

-- However, procedures and packages cannot gain privileges from a role
-- (because of dependency model; role set, grant, default, etc. would
-- invalidate procedure), so the HR package cannot execute the AppSec package.
-- We remedy this by granting execute on the AppSec package directly to HR.
GRANT EXECUTE ON appsec.app_sec_pkg TO hr;

-- Create HR.HR_SEC_PKG before continuing here

-- In contrast, the procedures in the HR package, they are called directly
-- by the AppUser applications (not by other procedures), so we can grant
-- access to a role that AppUser has -- HRView_Role
-- Give permission for HR App User to execute HR App Security procedures
-- Do this as HR user
--GRANT EXECUTE ON hr.hr_sec_pkg TO hrview_role;

-- Assure grants are made
SELECT * FROM sys.dba_tab_privs WHERE owner IN ( 'APPSEC', 'HR' );
