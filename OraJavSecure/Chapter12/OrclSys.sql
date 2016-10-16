-- Chapter12/OrclSys.sql
-- Copyright 2011, David Coffin

-- Connect as SYS using the SYSDBA "super" system privilege
--CONNECT sys AS sysdba;

-- Need with grant option so other schemas can see ojsaadm view based on this
GRANT SELECT ON sys.proxy_users TO ojsaadm WITH GRANT OPTION;


CREATE OR REPLACE PACKAGE sys.usr_role_adm_pkg IS

    PROCEDURE p_create_user_once( username sys.proxy_users.client%TYPE );

    PROCEDURE p_create_user_many( username sys.proxy_users.client%TYPE );

    PROCEDURE p_drop_user( username sys.proxy_users.client%TYPE );

    PROCEDURE p_set_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE );

    PROCEDURE p_drop_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE );

END usr_role_adm_pkg;
/

CREATE OR REPLACE PACKAGE BODY sys.usr_role_adm_pkg IS

    PROCEDURE p_create_user_once( username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'CREATE USER ' || username || ' IDENTIFIED EXTERNALLY';
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'user already exists for ' || username );
    END p_create_user_once;

    PROCEDURE p_create_user_many( username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'GRANT create_session_role TO ' || username;
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' GRANT CONNECT THROUGH appver';
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_create_user_many for ' || username );
    END p_create_user_many;

    PROCEDURE p_drop_user( username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' REVOKE CONNECT THROUGH appver';
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_drop_user for ' || username );
    END p_drop_user;

    PROCEDURE p_set_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' GRANT CONNECT THROUGH ' || proxyname;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_set_proxy_through for ' ||
                username || ' / ' || proxyname );
    END p_set_proxy_through;

    PROCEDURE p_drop_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' REVOKE CONNECT THROUGH ' || proxyname;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_drop_proxy_through for ' ||
                username || ' / ' || proxyname );
    END p_drop_proxy_through;

END usr_role_adm_pkg;
/

-- Grant to role
GRANT EXECUTE ON sys.usr_role_adm_pkg TO ojs_adm_admin;

-- Change how this role is granted - originally granted in Chapter 11
REVOKE appver_admin FROM osadmin;
-- Would do as appsec user, but not granted ALTER ROLE
ALTER ROLE appver_admin IDENTIFIED USING appsec.p_check_role_access;
