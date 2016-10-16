-- Chapter2/Sys.sql
-- Copyright 2011, David Coffin
-- Replace the placeholder "password" with a real, complex password

-- For our purposes, we are going to do the bare minimum as SYS
-- We will create a Security Administrator account
-- And give grants to that account to allow it to do all our administration
-- We will also remove grants from that account, if only needed temporarily

-- Connect as SYS using the SYSDBA "super" system privilege
--CONNECT sys AS sysdba;

-- Check who has the "super" system privileges
SELECT * FROM sys.v$pwfile_users;

-- Create a role of our own that only has create session
CREATE ROLE create_session_role NOT IDENTIFIED;
GRANT CREATE SESSION TO create_session_role;

-- Security Administrator
-- These scripts assume a default installation of Oracle 11g
-- if you have modified the default user privileges / profiles for new accounts
-- you may have to grant additional permissions
-- Warning:  Assign a complex password to this user
GRANT create_session_role TO secadm IDENTIFIED BY password;

-- Create a role for all Security Administrator privileges
CREATE ROLE secadm_role IDENTIFIED USING sys.p_check_secadm_access;

-- This is the Procedure that Identifies (authorizes) SECADM_ROLE
CREATE OR REPLACE PROCEDURE sys.p_check_secadm_access
AUTHID CURRENT_USER
AS
BEGIN
    -- This is a comment
    IF( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    THEN
        --DBMS_SESSION.SET_ROLE('secadm_role');
        EXECUTE IMMEDIATE 'SET ROLE secadm_role';
    END IF;
END;
/

-- All ow SECADM to execute the procedure
GRANT EXECUTE ON sys.p_check_secadm_access TO secadm;

-- Various system privileges are granted to SECADM_ROLE
GRANT
    CREATE USER
    ,ALTER USER
    ,CREATE ROLE
    ,GRANT ANY OBJECT PRIVILEGE
    ,GRANT ANY PRIVILEGE
    ,GRANT ANY ROLE
    ,CREATE ANY PROCEDURE
    ,CREATE ANY TRIGGER
    ,CREATE ANY CONTEXT
    ,CREATE PROFILE
    ,AUDIT SYSTEM
    ,AUDIT ANY
TO secadm_role;

-- SYS will configure auditing for the audit trail
AUDIT SELECT ON sys.dba_audit_trail BY ACCESS;
AUDIT SELECT ON sys.aud$ BY ACCESS;

-- View all users using the Data Dictionary
SELECT * FROM sys.dba_users;

-- Allow our Security Administrator role to see the more detailed views
-- in the Data Dictionary
GRANT select_catalog_role TO secadm_role;
