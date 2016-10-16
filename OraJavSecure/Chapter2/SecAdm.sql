-- Chapter2/SecAdm.sql
-- Copyright 2011, David Coffin
-- Modify IP Addresses and work hours in p_check_hrview_access
-- Replace the placeholder "password" with a real, complex password

-- Connect as our Security Administrator user
--CONNECT secadm;

-- Always execute procedure to acquire Security Administrator role
EXEC sys.p_check_secadm_access;

-- Execute these one at a time to toggle back and forth between roles
-- and observe the changes
SELECT * FROM sys.session_roles;
SET ROLE create_session_role;
SELECT * FROM sys.session_roles;
EXECUTE sys.p_check_secadm_access;
SELECT * FROM sys.session_roles;

-- Create a couple accounts for our use that can create sessions
-- Warning:  Assign a complex password to these users
-- Oracle Application (Java) Security
GRANT create_session_role TO appsec IDENTIFIED BY password;
-- Application User
GRANT create_session_role TO appusr IDENTIFIED BY password;

-- Role for privileges required by Application Security user
CREATE ROLE appsec_role NOT IDENTIFIED;
-- Give Application Security privilege to create Java Stored Procedures
GRANT CREATE PROCEDURE TO appsec_role;
-- Give Application Security privilege to create Tables and Views
GRANT CREATE TABLE TO appsec_role;
GRANT CREATE VIEW TO appsec_role;
-- Grant the role to APPSEC user
GRANT appsec_role TO appsec;

-- Make the APPSEC_ROLE a non-default role for the APPSEC user
ALTER USER appsec DEFAULT ROLE ALL EXCEPT appsec_role;

-- Secure Application Role for accessing HR schema
CREATE ROLE hrview_role IDENTIFIED USING appsec.p_check_hrview_access;

-- Procedure used to verify access to Secure Application Role
CREATE OR REPLACE PROCEDURE appsec.p_check_hrview_access
AUTHID CURRENT_USER
AS
BEGIN
    IF( ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    AND
        TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    )
    THEN
        EXECUTE IMMEDIATE 'SET ROLE hrview_role';
    END IF;
END;
/

-- Permit APPUSR to execute role verification procedure
GRANT EXECUTE ON appsec.p_check_hrview_access TO appusr;

-- Auditing SECADM structures and access to HR.EMPLOYEES
AUDIT ALTER ANY PROCEDURE BY ACCESS;
-- This is one of the recommended audit statements

AUDIT EXECUTE ON appsec.p_check_hrview_access
    BY ACCESS
    WHENEVER NOT SUCCESSFUL;

AUDIT SELECT ON hr.employees BY ACCESS;

-- If the HR user is not accessible, do this
-- Warning:  Assign a complex password to this user
ALTER USER hr ACCOUNT UNLOCK IDENTIFIED BY password;

-- After HR user creates the sensitive view, run the following
EXEC sys.p_check_secadm_access;

SELECT OBJECT_NAME, STATEMENT_TYPE, RETURNCODE FROM DBA_COMMON_AUDIT_TRAIL
WHERE DB_USER='HR'
ORDER BY EXTENDED_TIMESTAMP DESC;

EXEC sys.p_check_secadm_access;

SELECT OBJECT_NAME, STATEMENT_TYPE, RETURNCODE FROM DBA_COMMON_AUDIT_TRAIL
WHERE DB_USER='SECADM'
ORDER BY EXTENDED_TIMESTAMP DESC;

-- A RETURNCODE of 0 is a success, while a non-zero indicates a failure.
