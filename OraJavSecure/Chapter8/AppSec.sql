-- Chapter8/AppSec.sql
-- Copyright 2011, David Coffin
-- Modify IP Addresses and work hours in p_check_hrview_access

-- Connect as our Application User
--CONNECT appsec;

-- Enable the non-default role needed in order to create procedures
SET ROLE appsec_role;

-- Procedure used to verify access to Secure Application Role
-- This was initially defined in Chapter 2 - redefined here for proxy
CREATE OR REPLACE PROCEDURE appsec.p_check_hrview_access
AUTHID CURRENT_USER
AS
    just_os_user    VARCHAR2(40); -- Windows users are 20, allow 20 for domain
    backslash_place NUMBER;
BEGIN
    -- Upper case OS_USER and discard prepended domain name, if exists
    just_os_user := UPPER( SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    -- Back slash is not an escape character in this context
    -- Negative 1 indicates count left from the right end, get last backslash
    backslash_place := INSTR( just_os_user, '\', -1 );
    IF( backslash_place > 0 )
    THEN
        just_os_user := SUBSTR( just_os_user, backslash_place + 1 );
    END IF;
    --DBMS_OUTPUT.PUT_LINE( just_os_user );
    -- For proxy connections
    IF( SYS_CONTEXT( 'USERENV', 'PROXY_USER' ) = 'APPUSR'
    AND ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    AND SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) =
        SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
    AND SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = just_os_user )
    THEN
        EXECUTE IMMEDIATE 'SET ROLE hrview_role';
    END IF;
    -- For non-proxy connections
    IF( ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    AND SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) = 'APPUSR'
    AND SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = just_os_user )
    THEN
        --DBMS_SESSION.SET_ROLE('hrview_role');
        EXECUTE IMMEDIATE 'SET ROLE hrview_role';
    END IF;
END;
/

-- Permit PUBLIC to execute role verification procedure
-- This was initially defined in Chapter 2 - redefined here for proxy
GRANT EXECUTE ON appsec.p_check_hrview_access TO PUBLIC;
