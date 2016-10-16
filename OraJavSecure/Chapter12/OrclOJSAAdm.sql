-- Chapter12/OJSAAdm.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT ojsaadm;

SELECT * FROM sys.proxy_users;

-- Private database link to apver as ojsaadm
CREATE DATABASE LINK apver_link
CONNECT TO ojsaadm
IDENTIFIED BY password
USING 'apver';

CREATE OR REPLACE VIEW ojsaadm.instance_proxy_users AS
SELECT 'APVER' INSTANCE, proxy, client FROM sys.proxy_users@apver_link
UNION SELECT 'ORCL' INSTANCE, proxy, client FROM sys.proxy_users;

-- Test the link and view
SELECT * FROM ojsaadm.instance_proxy_users;

GRANT SELECT ON ojsaadm.instance_proxy_users TO ojs_adm_admin;
-- To let appsec read view across database link
-- This grant requires with grant option on sys.proxy_users
GRANT SELECT ON ojsaadm.instance_proxy_users TO appsec;

CREATE OR REPLACE PACKAGE ojsaadm.apver_usr_adm_pkg IS

    PROCEDURE p_create_apver_user( username VARCHAR2 );

    PROCEDURE p_drop_apver_user( username VARCHAR2 );

    PROCEDURE p_set_apver_proxy_through( username VARCHAR2, proxyname VARCHAR2 );

    PROCEDURE p_drop_apver_proxy_through( username VARCHAR2, proxyname VARCHAR2 );

    PROCEDURE p_grant_apver_appver_conns( username VARCHAR2 );

    PROCEDURE p_revoke_apver_appver_conns( username VARCHAR2 );

END apver_usr_adm_pkg;
/

CREATE OR REPLACE PACKAGE BODY ojsaadm.apver_usr_adm_pkg IS

    PROCEDURE p_create_apver_user( username VARCHAR2 )
    AS
        m_stmt VARCHAR2(100);
    BEGIN
        m_stmt := 'BEGIN sys.usr_role_adm_pkg.p_create_user_once@apver_link( :1 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username;
        m_stmt := 'BEGIN sys.usr_role_adm_pkg.p_create_user_many@apver_link( :1 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username;
    END p_create_apver_user;

    PROCEDURE p_drop_apver_user( username VARCHAR2 )
    AS
        m_stmt VARCHAR2(100);
    BEGIN
        m_stmt := 'BEGIN sys.usr_role_adm_pkg.p_drop_user@apver_link( :1 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username;
    END p_drop_apver_user;

    PROCEDURE p_set_apver_proxy_through( username VARCHAR2, proxyname VARCHAR2 )
    AS
        m_stmt VARCHAR2(100);
    BEGIN
        m_stmt := 'BEGIN sys.usr_role_adm_pkg.p_set_proxy_through@apver_link( :1, :2 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username, proxyname;
    END p_set_apver_proxy_through;

    PROCEDURE p_drop_apver_proxy_through( username VARCHAR2, proxyname VARCHAR2 )
    AS
        m_stmt VARCHAR2(100);
    BEGIN
        m_stmt := 'BEGIN sys.usr_role_adm_pkg.p_drop_proxy_through@apver_link( :1, :2 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username, proxyname;
    END p_drop_apver_proxy_through;

    PROCEDURE p_grant_apver_appver_conns( username VARCHAR2 )
    AS
        m_stmt VARCHAR2(100);
    BEGIN
        m_stmt := 'BEGIN sys.appver_conns_role_pkg.p_grant_appver_conns_role@apver_link( :1 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username;
    END p_grant_apver_appver_conns;

    PROCEDURE p_revoke_apver_appver_conns( username VARCHAR2 )
    AS
        m_stmt VARCHAR2(100);
    BEGIN
        m_stmt := 'BEGIN sys.appver_conns_role_pkg.p_revoke_appver_conns_role@apver_link( :1 ); END;';
        EXECUTE IMMEDIATE m_stmt USING username;
    END p_revoke_apver_appver_conns;

END apver_usr_adm_pkg;
/

-- Grant to role
GRANT EXECUTE ON ojsaadm.apver_usr_adm_pkg TO ojs_adm_admin;

