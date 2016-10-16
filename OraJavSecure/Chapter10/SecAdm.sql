-- Chapter10/SecAdm.sql
-- Copyright 2011, David Coffin
-- Replace OSUSER with your OS UserID
-- Replace the placeholder "password" with a real, complex password

-- Connect as our Security Administrator user
--CONNECT secadm;

-- Always execute procedure to acquire Security Administrator role
EXEC sys.p_check_secadm_access;

-- Execute commands in AppSec.sql before continuing
AUDIT EXECUTE ON appsec.p_check_role_access
    BY ACCESS
    WHENEVER NOT SUCCESSFUL;

DROP ROLE hrview_role;
-- Recreate Secure Application Role for accessing HR schema
CREATE ROLE hrview_role IDENTIFIED USING appsec.p_check_role_access;

-- After recreating role, redo grant
GRANT EXECUTE ON hr.hr_sec_pkg TO hrview_role;

-- Specify connect time and idle time in minutes - minimum is best
-- We need to maintain availability of this connection, so set
-- Unlimited Sessions, Password Lifetime and Failed Login Attempts
-- Limit burden this can put on server (DDOS) by limiting functionality
CREATE PROFILE appver_prof LIMIT
    CONNECT_TIME          1
    IDLE_TIME             1
    SESSIONS_PER_USER     UNLIMITED
    PASSWORD_LIFE_TIME    UNLIMITED
    FAILED_LOGIN_ATTEMPTS UNLIMITED;
-- Actually, sessions is limited by processes in database init.ora / pfile / spfile
-- default processes=150, set our specialized database (later) to 500

-- Go ahead and assign a password - this is one password that we use more like
-- an address.  It can be embedded into applications but is only useful for
-- application verification (identify an application to get access to resources)
CREATE USER appver
    IDENTIFIED BY password
    QUOTA 0 ON SYSTEM
    PROFILE appver_prof;

GRANT create_session_role TO appver;


-- Create APPSEC.P_APPVER_LOGON procedure before this
-- T_CHECK_APPVER_ACCESS is a logon trigger, only for the APPVER user
CREATE OR REPLACE TRIGGER secadm.t_screen_appver_access AFTER LOGON ON appver.SCHEMA
BEGIN
    appsec.p_appver_logon;
END;
/

ALTER USER osuser GRANT CONNECT THROUGH appver;


--AUDIT ALL STATEMENTS BY appver BY ACCESS; -- WHENEVER SUCCESSFUL;
AUDIT SELECT TABLE BY appver BY ACCESS;


AUDIT EXECUTE PROCEDURE
    BY appver
    BY ACCESS
    WHENEVER NOT SUCCESSFUL;

-- Increase quota to hold app verification data
ALTER USER appsec DEFAULT TABLESPACE USERS QUOTA 10M ON USERS;
