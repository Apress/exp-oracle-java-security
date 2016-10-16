-- Chapter12Single/OrclSys.sql
-- Copyright 2011, David Coffin
-- Replace OSADMIN with your OS UserID

-- Connect as SYS using the SYSDBA "super" system privilege
--CONNECT sys AS sysdba;

GRANT SELECT ON sys.proxy_users TO ojsaadm;


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

-- It is appsec user running the create Java in appsec_admin_pkg
-- Will need CREATE PROCEDURE
-- Non-default role not available
GRANT CREATE PROCEDURE TO appsec;
GRANT SELECT ON sys.all_java_classes TO appsec;


-- This role needed when only user proxy appver with create_session_role
-- Case when editing conn strings for alternate application
CREATE ROLE appver_conns NOT IDENTIFIED;
GRANT appver_conns TO osadmin;
GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_conns ;


CREATE OR REPLACE PACKAGE sys.appver_conns_role_pkg IS

    PROCEDURE p_grant_appver_conns_role (
        username sys.proxy_users.client%TYPE );

    PROCEDURE p_revoke_appver_conns_role (
        username sys.proxy_users.client%TYPE );

END appver_conns_role_pkg;
/

CREATE OR REPLACE PACKAGE BODY sys.appver_conns_role_pkg IS

    PROCEDURE p_grant_appver_conns_role (
        username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'GRANT appver_conns TO ' || username;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.p_grant_appver_conns_role for ' ||
                username );
    END p_grant_appver_conns_role;

    PROCEDURE p_revoke_appver_conns_role (
        username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'REVOKE appver_conns FROM ' || username;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.p_revoke_appver_conns_role for ' ||
                username );
    END p_revoke_appver_conns_role;

END appver_conns_role_pkg;
/

-- From New Application Registration
GRANT EXECUTE ON sys.appver_conns_role_pkg TO appver_admin ;

-- From Admin Users, Grant to user, not to role
GRANT EXECUTE ON sys.appver_conns_role_pkg TO ojsaadm;


-- Need with grant option so other schemas can see appsec view based on this
GRANT SELECT ON SYS.DBA_TAB_PRIVS TO APPSEC WITH GRANT OPTION;

GRANT EXECUTE ON SYS.DBMS_RLS TO appsec;
