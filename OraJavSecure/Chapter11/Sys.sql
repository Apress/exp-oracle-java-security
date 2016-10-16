-- Chapter11/Sys.sql
-- Copyright 2011, David Coffin

-- Connect as SYS using the SYSDBA "super" system privilege
--CONNECT sys AS sysdba;

-- Must grant to user, not role since roles not exist without session
GRANT EXECUTE ON sys.dbms_crypto TO appsec;

-- Will be used to manage Application Verification Data
CREATE ROLE appver_admin NOT IDENTIFIED;

-- Grant APPVER_ADMIN role to each user who is allowed to update / copy connection strings
GRANT appver_admin TO osadmin;
