-- Chapter10/Sys.sql
-- Copyright 2011, David Coffin

-- Connect as SYS using the SYSDBA "super" system privilege
--CONNECT sys AS sysdba;


-- Wish this worked - Can't kill current session
-- Could insert current sesion credentials in a table
-- for an independent process to kill
CREATE OR REPLACE FUNCTION sys.f_get_off
RETURN VARCHAR2
AS
    PRAGMA AUTONOMOUS_TRANSACTION;
    p_sid v$session.SID%TYPE;
    p_serial v$session.serial#%TYPE;
BEGIN
    p_sid := SYS_CONTEXT( 'USERENV', 'SID' );
    SELECT serial# INTO p_serial
    FROM v$session
    WHERE sid = p_sid;
    EXECUTE IMMEDIATE 'ALTER SYSTEM KILL SESSION ''' ||
                 p_sid || ',' || p_serial || '''';
    RETURN 'OFF';
END f_get_off;

GRANT EXECUTE ON sys.f_get_off TO appsec;

