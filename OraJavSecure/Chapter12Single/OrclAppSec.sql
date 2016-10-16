-- Chapter12Single/OrclAppSec.sql
-- Copyright 2011, David Coffin
-- Replace OSADMIN with your OS UserID -- NOTE: Uppercase in INSERTS

-- Connect as our Application User
--CONNECT appsec;

-- Enable non-default role
SET ROLE appsec_role;

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','APPUSR','HRVIEW_ROLE');

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','OJSAADM','OJS_ADM_ADMIN');

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','AVADMIN','APPVER_ADMIN');

COMMIT;


CREATE OR REPLACE PACKAGE appsec.appsec_admin_pkg IS

    PROCEDURE p_create_template_class(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_err_no     OUT NUMBER,
        m_err_txt    OUT VARCHAR2 );

    FUNCTION f_set_decrypt_conns( class_instance RAW, connections RAW )
    RETURN VARCHAR2;

    PROCEDURE p_copy_app_conns(
        m_two_factor_cd      v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_class_instance     v_app_conn_registry.class_instance%TYPE,
        m_prev_version       v_app_conn_registry.class_version%TYPE,
        m_application_id     v_two_fact_cd_cache.application_id%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 );

END appsec_admin_pkg;
/

CREATE OR REPLACE PACKAGE BODY appsec.appsec_admin_pkg IS

    PROCEDURE p_create_template_class(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_err_no     OUT NUMBER,
        m_err_txt    OUT VARCHAR2 )
    IS
        v_count   INTEGER;
        v_package v_app_conn_registry.class_name%TYPE;
    BEGIN
        m_err_no := 0;
        SELECT COUNT(*) INTO v_count
        FROM sys.all_java_classes
        WHERE owner='APPSEC' AND name = m_class_name;
        IF v_count < 1 THEN
            v_count := INSTR( m_class_name, 'Login' );
            IF v_count > 0 THEN
                v_package := SUBSTR( m_class_name, 0, v_count - 2 );
                IF LENGTH( v_package ) > 0 THEN
                    EXECUTE IMMEDIATE
'CREATE AND RESOLVE JAVA SOURCE NAMED APPSEC.' || CHR(34) ||
v_package || '/Login' || CHR(34) || ' AS ' || CHR(13) || CHR(10) ||
'package ' || v_package || '; ' || CHR(13) || CHR(10) ||
'import java.io.Serializable; ' || CHR(13) || CHR(10) ||
'import orajavsec.RevLvlClassIntfc; ' || CHR(13) || CHR(10) ||
'public class Login { ' || CHR(13) || CHR(10) ||
'    public static class InnerRevLvlClass ' || CHR(13) || CHR(10) ||
'       implements Serializable, RevLvlClassIntfc{ ' || CHR(13) || CHR(10) ||
'        private static final long serialVersionUID = 2011010100L; ' || CHR(13) || CHR(10) ||
'        private String innerClassRevLvl = "20110101a"; ' || CHR(13) || CHR(10) ||
'        public String getRevLvl() { ' || CHR(13) || CHR(10) ||
'            return innerClassRevLvl; ' || CHR(13) || CHR(10) ||
'}   }   }';
                END IF;
            END IF;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'p_create_template_class' );
    END p_create_template_class;

    FUNCTION f_set_decrypt_conns( class_instance RAW, connections RAW )
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.setDecryptConns( oracle.sql.RAW, oracle.sql.RAW ) return java.lang.String';

    PROCEDURE p_copy_app_conns(
        m_two_factor_cd      v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_class_instance     v_app_conn_registry.class_instance%TYPE,
        m_prev_version       v_app_conn_registry.class_version%TYPE,
        m_application_id     v_two_fact_cd_cache.application_id%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 )
    IS
        return_user VARCHAR2(40);
        m_app_user  v_application_registry.app_user%TYPE := 'APPVER';
    BEGIN
        m_err_no := 0;
        return_user := f_is_sso( m_app_user );
        IF( return_user IS NOT NULL )
        THEN
            IF( m_two_factor_cd IS NULL )
            THEN
                m_err_txt := appsec_only_pkg.f_send_2_factor( return_user, m_application_id );
            ELSIF( appsec_only_pkg.f_is_cur_cached_cd( return_user, m_application_id, m_two_factor_cd )
                = 'Y' )
            THEN
                -- Reuse existing VARCHAR2, RETURN_USER
                return_user := appsec_only_pkg.f_copy_conns( m_class_instance, m_prev_version );
            ELSE
                -- Wrong 2-Factor code entered
                RAISE NO_DATA_FOUND;
            END IF;
            app_sec_pkg.p_log_error( 0, 'Success copying App Conns, ' || return_user );
        ELSE
            app_sec_pkg.p_log_error( 0, 'Problem copying App Conns, ' || return_user );
        END IF;
    -- Raise Exceptions
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'p_copy_app_conns' );
    END p_copy_app_conns;

END appsec_admin_pkg;
/

-- Administrator users who can access applications
CREATE TABLE appsec.t_application_admins
(
    -- match appsec.t_app_conn_registry.class_name
    class_name VARCHAR2(2000) NOT NULL,
    -- match hr.emp_mobile_nos.user_id
    user_id    VARCHAR2(20) NOT NULL
);
/

CREATE UNIQUE INDEX application_admins_pk ON appsec.t_application_admins
    ( class_name, user_id );

ALTER TABLE appsec.t_application_admins ADD (
    CONSTRAINT application_admins_pk
    PRIMARY KEY
    ( class_name, user_id )
    USING INDEX application_admins_pk
);
/

CREATE OR REPLACE VIEW appsec.v_application_admins
    AS SELECT * FROM appsec.t_application_admins;

INSERT INTO appsec.v_application_admins
    ( class_name, user_id )
    ( SELECT DISTINCT class_name, 'OSADMIN' FROM appsec.t_app_conn_registry );

INSERT INTO appsec.v_application_admins
    ( class_name, user_id ) VALUES
    ( 'orajavsec.Login$InnerRevLvlClass', 'OSADMIN' );

COMMIT;


CREATE TABLE appsec.t_app_class_id
(
    class_name    VARCHAR2(2000 BYTE) NOT NULL ENABLE,
    application_id VARCHAR2(24 BYTE) NOT NULL ENABLE
);
/

CREATE UNIQUE INDEX app_class_id_pk ON appsec.t_app_class_id
    ( class_name, application_id );

ALTER TABLE appsec.t_app_class_id ADD (
    CONSTRAINT app_class_id_pk
    PRIMARY KEY
    ( class_name, application_id )
    USING INDEX app_class_id_pk
);
/

CREATE OR REPLACE VIEW appsec.v_app_class_id AS SELECT * FROM appsec.t_app_class_id;

INSERT INTO appsec.v_app_class_id
(CLASS_NAME, APPLICATION_ID) VALUES
('testojs.TestOracleJavaSecure$AnyNameWeWant','HRVIEW');

INSERT INTO appsec.v_app_class_id
(CLASS_NAME, APPLICATION_ID) VALUES
('orajavsec.Login$InnerRevLvlClass','OJSADMIN');

COMMIT;

GRANT SELECT ON appsec.v_app_class_id TO appver_admin ;
GRANT SELECT ON appsec.v_application_registry TO appver_admin;
GRANT SELECT ON appsec.v_app_conn_registry TO appver_admin;

GRANT INSERT ON appsec.v_app_class_id TO appver_admin ;
GRANT INSERT ON appsec.v_application_registry TO appver_admin ;
GRANT INSERT ON appsec.v_application_admins TO appver_admin;

GRANT UPDATE, SELECT, DELETE ON appsec.v_application_admins TO osadmin;

-- Oracle Virtual Private Database policy
-- Dynamic Where Clause
-- Fine-Grained Access Control (using ID from session)
-- Function to create Dynamic WHERE Clause
-- Policy to attach function to structure you will protect

CREATE OR REPLACE FUNCTION appsec.apps_for_admin(
    m_schema_nm VARCHAR2,
    m_table_nm  VARCHAR2 )
RETURN VARCHAR2
IS
    rtrn_clause VARCHAR2(400);
BEGIN
    appsec.app_sec_pkg.p_log_error( 121, 'dave',
    'appsec.apps_for_admin: ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );

    rtrn_clause :=
    'class_name IN ( SELECT class_name FROM appsec.t_application_admins '
    || 'WHERE user_id = SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' ) ) '
    || 'OR SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' ) = '
    || '( SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS '
    || '  WHERE TABLE_NAME=''V_APPLICATION_ADMINS'' '
    || '  AND OWNER=''APPSEC'' '
    || '  AND PRIVILEGE=''UPDATE'' '
    || '  AND GRANTEE=SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' ) )';
    RETURN rtrn_clause;
END apps_for_admin;
/

-- VPD policy applies to t_app_conn_registry table
-- For efficiency, this policy is STATIC - will reside in SGA
-- Dynamic based on SYS_CONTEXT - fine-grained access control
-- Any column in query, hide rows by filter (not column-masking)
-- Only the INSERT, UPDATE and DELETE statement types
BEGIN
DBMS_RLS.ADD_POLICY (
    object_schema => 'appsec',
    object_name => 't_app_conn_registry',
    policy_name => 'apps_for_admin_policy',
    function_schema => 'appsec',
    policy_function => 'apps_for_admin',
    statement_types => 'INSERT,UPDATE,DELETE',
    policy_type => DBMS_RLS.STATIC );
END;
/




--GRANT EXEMPT ACCESS POLICY TO appsec; -- not needed for schema owner
--revoke EXEMPT ACCESS POLICY from appsec;

-- Modified for Single - not across link
CREATE OR REPLACE FUNCTION appsec.apps_for_user(
    m_schema_nm VARCHAR2,
    m_table_nm  VARCHAR2 )
RETURN VARCHAR2
IS
    rtrn_clause VARCHAR2(400);
BEGIN
--    appsec.app_sec_pkg.p_log_error( 122, 'dave',
--    'appsec.apps_for_user: ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );

    rtrn_clause :=
    'class_name IN ( SELECT class_name FROM appsec.t_app_class_id '
    || 'WHERE application_id IN ( '
    || 'SELECT application_id FROM appsec.t_application_registry '
    || 'WHERE app_user IN ( '
    || 'SELECT proxy FROM ojsaadm.instance_proxy_users '
    || 'WHERE client = SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' ))) '
    || 'UNION SELECT class_name FROM appsec.t_application_admins '
    || 'WHERE user_id = SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' ) '
    || 'OR SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' ) = ( '
    || 'SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS '
    || 'WHERE TABLE_NAME=''V_APPLICATION_ADMINS'' '
    || 'AND OWNER=''APPSEC'' '
    || 'AND PRIVILEGE=''UPDATE'' '
    || 'AND GRANTEE=SYS_CONTEXT( ''USERENV'', ''CLIENT_IDENTIFIER'' )))';
    RETURN rtrn_clause;
END apps_for_user;
/



-- VPD policy applies to t_app_conn_registry table
-- For efficiency, this policy is STATIC - will reside in SGA
-- Dynamic based on SYS_CONTEXT - fine-grained access control
-- Any column in query, hide rows by filter (not column-masking)
-- Only the INSERT, UPDATE and DELETE statement types
BEGIN
DBMS_RLS.ADD_POLICY (
    object_schema => 'appsec',
    object_name => 't_app_conn_registry',
    policy_name => 'apps_for_user_policy',
    function_schema => 'appsec',
    policy_function => 'apps_for_user',
    statement_types => 'SELECT',
    policy_type => DBMS_RLS.STATIC );
END;
/



-- VPD works except when access t_app_conn_registry through procedures in appsec packages
-- Although, adds a bit of confusion, so drop the policies
BEGIN
DBMS_RLS.DROP_POLICY (
    object_schema => 'appsec',
    object_name => 't_app_conn_registry',
    policy_name => 'apps_for_admin_policy' );
END;
/
BEGIN
DBMS_RLS.DROP_POLICY (
    object_schema => 'appsec',
    object_name => 't_app_conn_registry',
    policy_name => 'apps_for_user_policy' );
END;
/


-- Instead, update code of p_get_class_conns and p_set_class_conns
-- This is a combination of standard Chapter12 and non-apver Chapter11
-- Remove reference to and select from across a link
CREATE OR REPLACE PACKAGE BODY appsec.appsec_only_pkg IS

    -- New in Chapter 11
    FUNCTION f_copy_conns( class_instance RAW, class_version VARCHAR2 )
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.copyPreviousConns( oracle.sql.RAW, java.lang.String ) return java.lang.String';

    FUNCTION f_is_cur_cached_cd(
        just_os_user     VARCHAR2,
        m_application_id v_two_fact_cd_cache.application_id%TYPE,
        m_two_factor_cd  v_two_fact_cd_cache.two_factor_cd%TYPE )
    RETURN VARCHAR2
    AS
        return_char          VARCHAR2(1) := 'N';
        cache_timeout_mins   NUMBER := 10;
        cached_two_factor_cd v_two_fact_cd_cache.two_factor_cd%TYPE;
    BEGIN
        SELECT c.two_factor_cd INTO cached_two_factor_cd
        FROM v_two_fact_cd_cache c, hr.v_emp_mobile_nos m
        WHERE m.employee_id = c.employee_id
        AND m.user_id = just_os_user
        AND c.application_id = m_application_id
        AND c.ip_address = SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' )
        AND ( SYSDATE - c.cache_ts )*24*60 < cache_timeout_mins;
        IF cached_two_factor_cd = m_two_factor_cd
        THEN
            return_char := 'Y';
        END IF;
        RETURN return_char;
    END f_is_cur_cached_cd;

    -- Use APPLICATION_ID as Title for message, where allowed
    FUNCTION f_send_2_factor(
        just_os_user     VARCHAR2,
        m_application_id v_two_fact_cd_cache.application_id%TYPE )
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.distribute2Factor( java.lang.String, java.lang.String ) return java.lang.String';

    -- Cannot read V_APPLICATION_REGISTRY directly from P_CHECK_ROLE_ACCESS
    -- since not granted to PUBLIC and executing as AUTHID CURRENT_USER,
    -- So get role name from helper function which will execute
    -- from Secure Application Role procedure without PUBLIC grant
    FUNCTION f_get_app_role(
        m_application_id v_two_fact_cd_cache.application_id%TYPE,
        m_app_user       v_application_registry.app_user%TYPE )
    RETURN VARCHAR2
    AS
        m_app_role v_application_registry.app_role%TYPE;
    BEGIN
        SELECT app_role INTO m_app_role
        FROM v_application_registry
        WHERE application_id = m_application_id
        AND app_user = m_app_user;
        RETURN m_app_role;
    END f_get_app_role;

    PROCEDURE p_get_emp_2fact_nos(
        os_user               hr.v_emp_mobile_nos.user_id%TYPE,
        fmt_string            VARCHAR2,
        m_employee_id     OUT hr.v_emp_mobile_nos.employee_id%TYPE,
        m_com_pager_no    OUT hr.v_emp_mobile_nos.com_pager_no%TYPE,
        m_sms_phone_no    OUT hr.v_emp_mobile_nos.sms_phone_no%TYPE,
        m_sms_carrier_url OUT hr.v_sms_carrier_host.sms_carrier_url%TYPE,
        m_email           OUT hr.v_employees_public.email%TYPE,
        m_ip_address      OUT v_two_fact_cd_cache.ip_address%TYPE,
        m_cache_ts        OUT VARCHAR2,
        m_cache_addr      OUT v_two_fact_cd_cache.ip_address%TYPE,
        m_application_id      v_two_fact_cd_cache.application_id%TYPE,
        m_err_no          OUT NUMBER,
        m_err_txt         OUT VARCHAR2 )
    IS BEGIN
        m_err_no := 0;
        SELECT e.employee_id, m.com_pager_no, m.sms_phone_no, s.sms_carrier_url,
            e.email, SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ),
            TO_CHAR( c.cache_ts, fmt_string ), c.ip_address
        INTO m_employee_id, m_com_pager_no, m_sms_phone_no, m_sms_carrier_url,
            m_email, m_ip_address, m_cache_ts, m_cache_addr
        FROM hr.v_emp_mobile_nos m, hr.v_employees_public e,
            hr.v_sms_carrier_host s, v_two_fact_cd_cache c
        WHERE m.user_id = os_user
        AND e.employee_id =  m.employee_id
        AND s.sms_carrier_cd (+)=  m.sms_carrier_cd
        AND c.employee_id (+)= m.employee_id
        AND c.application_id (+)= m_application_id;
    EXCEPTION
        -- User must exist in HR.V_EMP_MOBILE_NOS to send 2Factor, even to email
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'appsec_only_pkg.p_get_emp_2fact_nos' );
    END p_get_emp_2fact_nos;

    PROCEDURE p_update_2fact_cache(
        m_employee_id        v_two_fact_cd_cache.employee_id%TYPE,
        m_application_id     v_two_fact_cd_cache.application_id%TYPE,
        m_two_factor_cd      v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_distrib_cd         v_two_fact_cd_cache.distrib_cd%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 )
    IS
        v_count          INTEGER;
    BEGIN
        m_err_no := 0;
        SELECT COUNT(*) INTO v_count
            FROM v_two_fact_cd_cache
            WHERE employee_id = m_employee_id
            AND application_id = m_application_id;
        IF v_count = 0 THEN
            INSERT INTO v_two_fact_cd_cache( employee_id, application_id,
                two_factor_cd, distrib_cd ) VALUES
            ( m_employee_id, m_application_id, m_two_factor_cd, m_distrib_cd );
        ELSE
            UPDATE v_two_fact_cd_cache SET two_factor_cd = m_two_factor_cd,
                ip_address = SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ),
                distrib_cd = m_distrib_cd, cache_ts=SYSDATE
            WHERE employee_id = m_employee_id
            AND application_id = m_application_id;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'app_sec_pkg.p_update_2fact_cache' );
    END p_update_2fact_cache;

    FUNCTION f_is_user( just_os_user VARCHAR2 )
    RETURN VARCHAR2
    AS
        return_char VARCHAR2(1) := 'N';
        v_count     INTEGER;
    BEGIN
        SELECT COUNT(*) INTO v_count
        FROM sys.all_users
        WHERE username = just_os_user;
        IF v_count > 0 THEN
            return_char := 'Y';
        END IF;
        RETURN return_char;
    END f_is_user;

    PROCEDURE p_count_class_conns(
        m_class_name         v_app_conn_registry.class_name%TYPE,
        m_class_version      v_app_conn_registry.class_version%TYPE,
        m_count          OUT NUMBER )
    IS BEGIN
        SELECT COUNT(*)
        INTO m_count
        FROM v_app_conn_registry
        WHERE class_name = m_class_name
        AND class_version = m_class_version;
    END p_count_class_conns;

    PROCEDURE p_get_class_conns(
        m_class_name         v_app_conn_registry.class_name%TYPE,
        m_class_version      v_app_conn_registry.class_version%TYPE,
        m_class_instance OUT v_app_conn_registry.class_instance%TYPE,
        m_connections    OUT v_app_conn_registry.connections%TYPE )
    IS BEGIN
        --appsec.app_sec_pkg.p_log_error( 125, 'dave',
        --'p_get_class_conns for: ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );
        SELECT class_instance, connections
        INTO m_class_instance, m_connections
        FROM appsec.v_app_conn_registry
        WHERE class_name = m_class_name
        AND class_version = m_class_version
        AND class_name IN ( SELECT class_name FROM appsec.v_app_class_id
        WHERE application_id IN (
        SELECT application_id FROM appsec.v_application_registry
        WHERE app_user IN (
        --SELECT proxy FROM ojsaadm.instance_proxy_users@orcl_link
        SELECT proxy FROM ojsaadm.instance_proxy_users
        WHERE client = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )))
        UNION SELECT class_name FROM appsec.v_application_admins
        WHERE user_id = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
        OR SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = (
        SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
        WHERE TABLE_NAME='V_APPLICATION_ADMINS'
        AND OWNER='APPSEC'
        AND PRIVILEGE='UPDATE'
        AND GRANTEE=SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )));
    END p_get_class_conns;

    PROCEDURE p_set_class_conns(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_class_version  v_app_conn_registry.class_version%TYPE,
        m_class_instance v_app_conn_registry.class_instance%TYPE,
        m_connections    v_app_conn_registry.connections%TYPE )
    IS
        v_count INTEGER;
        v_count_able INTEGER;
    BEGIN
        --appsec.app_sec_pkg.p_log_error( 126, 'dave',
        --'p_set_class_conns for: ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );
        SELECT COUNT(*) INTO v_count
            FROM appsec.v_app_conn_registry
            WHERE class_name = m_class_name
            AND class_version = m_class_version;
        SELECT COUNT(*) INTO v_count_able
            FROM appsec.v_app_conn_registry
            WHERE class_name = m_class_name
            AND class_version = m_class_version
            AND class_name IN (
            SELECT class_name FROM appsec.v_application_admins
            WHERE user_id = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
            OR SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = (
            SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
            WHERE TABLE_NAME='V_APPLICATION_ADMINS'
            AND OWNER='APPSEC'
            AND PRIVILEGE='UPDATE'
            AND GRANTEE=SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )));
        IF v_count = 0 THEN
            INSERT INTO v_app_conn_registry ( class_name, class_version,
                class_instance, connections ) VALUES
                ( m_class_name, m_class_version, m_class_instance, m_connections );
        ELSE
            IF v_count_able > 0 THEN
                UPDATE v_app_conn_registry
                    SET class_instance = m_class_instance,
                    connections = m_connections, update_dt = SYSDATE
                WHERE class_name = m_class_name
                AND class_version = m_class_version;
            END IF;
        END IF;
    END p_set_class_conns;

    FUNCTION f_get_crypt_conns(
        class_instance  v_app_conn_registry.class_instance%TYPE )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptConns( oracle.sql.RAW ) return oracle.sql.RAW';

END appsec_only_pkg;
/


--delete from appsec.v_appsec_errors;
--commit;

--select * from sys.all_java_classes where owner='APPSEC';
--select * from all_views where view_name like '%JAVA%';

--select * from dba_tab_privs where owner='APPSEC';

--select * from all_views where view_name like '%ROLE%';

--select * from user_role_privs where granted_role='APPVER_ADMIN';

--select * from appsec.v_two_fact_cd_cache;

-- with Modify Connection Strings screen
-- Modify putAppConnString to return a message

-- Hint to drop java object
-- DROP JAVA SOURCE appsec."badpackage/Login";

-- This depends on appsec having grant option on select from dba_tab_privs
CREATE OR REPLACE VIEW appsec.v_app_conn_registry_filtered
AS
    SELECT * FROM appsec.t_app_conn_registry
    WHERE class_name IN (
        SELECT class_name FROM appsec.v_application_admins
        WHERE user_id = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
    OR SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = (
        SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
        WHERE TABLE_NAME='V_APPLICATION_ADMINS'
        AND OWNER='APPSEC'
        AND PRIVILEGE='UPDATE'
        AND GRANTEE=SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )));

GRANT SELECT ON appsec.v_app_conn_registry_filtered TO appver_admin;

-- Assure this did not get revoked / dropped
GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_admin ;

-- NOTE!!! - If you are retaining VPD policies,
-- you will not be able to do this first query
-- unless you have your CLIENT_IDENTIFIER set !!!

-- Test these dynamic where clauses by substituting
-- various usernames for 'OSADMIN' in these queries
-- NONEAD, USERAD, ROLEAD, APVRAD, USERONE, USERTWO, USERTHREE, USERFOUR
    SELECT * FROM appsec.t_app_conn_registry
    WHERE class_name IN (
        SELECT class_name FROM appsec.v_application_admins
        WHERE user_id = 'OSADMIN'
    OR 'OSADMIN' = (
        SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
        WHERE TABLE_NAME='V_APPLICATION_ADMINS'
        AND OWNER='APPSEC'
        AND PRIVILEGE='UPDATE'
        AND GRANTEE='OSADMIN'));

    SELECT class_name FROM appsec.v_app_class_id
        WHERE application_id IN (
        SELECT application_id FROM appsec.v_application_registry
        WHERE app_user IN (
        SELECT proxy FROM ojsaadm.instance_proxy_users
        WHERE client = 'OSADMIN'))
        UNION SELECT class_name FROM appsec.v_application_admins
        WHERE user_id = 'OSADMIN'
        OR 'OSADMIN' = (
        SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
        WHERE TABLE_NAME='V_APPLICATION_ADMINS'
        AND OWNER='APPSEC'
        AND PRIVILEGE='UPDATE'
        AND GRANTEE='OSADMIN');
