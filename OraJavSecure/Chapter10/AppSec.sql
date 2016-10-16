-- Chapter10/AppSec.sql
-- Copyright 2011, David Coffin
-- Modify IP Addresses in f_is_sso and p_appver_logon

-- Connect as our Application User
--CONNECT appsec;

-- Enable non-default role
SET ROLE appsec_role;

CREATE TABLE appsec.t_application_registry
(
    application_id VARCHAR2(24 BYTE) NOT NULL,
    app_user       VARCHAR2(20 BYTE) NOT NULL,
    app_role       VARCHAR2(20 BYTE) NOT NULL
);

CREATE UNIQUE INDEX appsec.application_registry_pk ON appsec.t_application_registry
    (application_id, app_user);

ALTER TABLE appsec.t_application_registry ADD (
    CONSTRAINT application_registry_pk
    PRIMARY KEY
    (application_id, app_user)
    USING INDEX application_registry_pk
);

CREATE OR REPLACE VIEW appsec.v_application_registry AS SELECT * FROM appsec.t_application_registry;

INSERT INTO appsec.v_application_registry
( application_id, app_user, app_role )
VALUES
( 'HRVIEW', 'APPUSR', 'HRVIEW_ROLE' );

-- Add an column to primary key of T_TWO_FACT_CD_CACHE
DROP TABLE appsec.t_two_fact_cd_cache CASCADE CONSTRAINTS;

-- Create table to cache 2-factor codes by user and application
-- Initial 2-Factor Code length = 14, allow for 24
-- IPv4 addresses are 15 characters or less;
-- IPv6, 39 characters, 45 mapped to IPv4
CREATE TABLE appsec.t_two_fact_cd_cache
(
    employee_id    NUMBER(6) NOT NULL,
    application_id VARCHAR2(24 BYTE) NOT NULL,
    two_factor_cd  VARCHAR2(24 BYTE),
    ip_address     VARCHAR2(45 BYTE) DEFAULT SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ),
    distrib_cd     NUMBER(1),
    cache_ts       DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX two_fact_cd_emp_id_pk ON appsec.t_two_fact_cd_cache
    (employee_id,application_id);

ALTER TABLE appsec.t_two_fact_cd_cache ADD (
    CONSTRAINT two_fact_cd_emp_id_pk
    PRIMARY KEY
    (employee_id,application_id)
    USING INDEX two_fact_cd_emp_id_pk
);

CREATE OR REPLACE VIEW appsec.v_two_fact_cd_cache AS SELECT * FROM appsec.t_two_fact_cd_cache;

INSERT INTO appsec.v_two_fact_cd_cache
( employee_id, application_id, two_factor_cd )
VALUES
( 300, 'HRVIEW', 'FAKE' );

-- Tests
SELECT * FROM appsec.v_two_fact_cd_cache;
-- After timeout, restart cache aging for this entry
UPDATE appsec.v_two_fact_cd_cache
SET two_factor_cd = 'Fake2', ip_address = '127.0.0.1', cache_ts=SYSDATE
WHERE employee_id=300 AND application_id='HRVIEW';

-- NOTE: Use only small (<2K) class instances, else define LOB Storage Clause
-- Must store class instances as RAW, not BLOB -- BLOB not instantiated in
-- Oracle JVM in same way -- difficult to test equality of instances
CREATE TABLE appsec.t_app_conn_registry
(
    class_name      VARCHAR2(2000) NOT NULL,
    class_version   VARCHAR2(200) NOT NULL,
    class_instance  RAW(2000),
    update_dt       DATE DEFAULT SYSDATE,
    connections     BLOB DEFAULT EMPTY_BLOB()
);

CREATE UNIQUE INDEX app_conn_registry_nam_ver_pk ON appsec.t_app_conn_registry
    (class_name, class_version);

ALTER TABLE appsec.t_app_conn_registry ADD (
    CONSTRAINT app_conn_registry_nam_ver_pk
    PRIMARY KEY
    (class_name, class_version)
    USING INDEX app_conn_registry_nam_ver_pk
);

CREATE OR REPLACE VIEW appsec.v_app_conn_registry AS SELECT * FROM appsec.t_app_conn_registry;

DROP PROCEDURE appsec.p_check_hrview_access;

-- Move existing procedures and functions to packages
DROP FUNCTION appsec.f_is_cur_cached_cd;
DROP FUNCTION appsec.f_send_2_factor;

-- Procedures and Functions with AUTHID CURRENT_USER must be at top level
-- (not in packages)

CREATE OR REPLACE FUNCTION appsec.f_is_sso( m_app_user VARCHAR2 )
RETURN VARCHAR2
AUTHID CURRENT_USER
AS
    return_user     VARCHAR2(40) := '';
    just_os_user    VARCHAR2(40);
    backslash_place NUMBER;
BEGIN
    just_os_user := UPPER( SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    backslash_place := INSTR( just_os_user, '\', -1 );
    IF( backslash_place > 0 )
    THEN
        just_os_user := SUBSTR( just_os_user, backslash_place + 1 );
    END IF;
    --app_sec_pkg.p_log_error( 0, 'OS_USER) ' || SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    --app_sec_pkg.p_log_error( 0, 'PROXY_USER) ' || SYS_CONTEXT( 'USERENV', 'PROXY_USER' ) );
    --app_sec_pkg.p_log_error( 0, 'IP_ADDRESS) ' || SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) );
    --app_sec_pkg.p_log_error( 0, 'SESSION_USER) ' || SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) );
    --app_sec_pkg.p_log_error( 0, 'CLIENT_IDENTIFIER) ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );
    -- For proxy connections
    IF( SYS_CONTEXT( 'USERENV', 'PROXY_USER' ) = m_app_user
    AND ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    -- Requirements must be applicable to all applications - time may not be
    --AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    AND SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) =
        SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
    AND SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = just_os_user )
    THEN
        return_user := just_os_user;
    END IF;
    -- For non-proxy connections
    IF( SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) = m_app_user
    AND ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    -- Requirements must be applicable to all applications - time may not be
    --AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    AND SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = just_os_user )
    THEN
        return_user := just_os_user;
    END IF;
    RETURN return_user;
END f_is_sso;
/

CREATE OR REPLACE PACKAGE appsec.appsec_only_pkg IS

    FUNCTION f_is_cur_cached_cd(
        just_os_user     VARCHAR2,
        m_application_id v_two_fact_cd_cache.application_id%TYPE,
        m_two_factor_cd  v_two_fact_cd_cache.two_factor_cd%TYPE )
    RETURN VARCHAR2;

    FUNCTION f_send_2_factor(
        just_os_user     VARCHAR2,
        m_application_id v_two_fact_cd_cache.application_id%TYPE )
    RETURN VARCHAR2;

    -- Cannot read V_APPLICATION_REGISTRY directly from P_CHECK_ROLE_ACCESS
    -- since not granted to PUBLIC and executing as AUTHID CURRENT_USER,
    -- So get role name from helper function which will execute
    -- from Secure Application Role procedure without PUBLIC grant
    FUNCTION f_get_app_role(
        m_application_id v_two_fact_cd_cache.application_id%TYPE,
    	m_app_user       v_application_registry.app_user%TYPE )
    RETURN VARCHAR2;

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
        m_err_txt         OUT VARCHAR2 );

    PROCEDURE p_update_2fact_cache(
        m_employee_id        v_two_fact_cd_cache.employee_id%TYPE,
        m_application_id     v_two_fact_cd_cache.application_id%TYPE,
        m_two_factor_cd      v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_distrib_cd         v_two_fact_cd_cache.distrib_cd%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 );

    FUNCTION f_is_user( just_os_user VARCHAR2 )
    RETURN VARCHAR2;

    PROCEDURE p_count_class_conns(
        m_class_name         v_app_conn_registry.class_name%TYPE,
        m_class_version      v_app_conn_registry.class_version%TYPE,
        m_count          OUT NUMBER );

    PROCEDURE p_get_class_conns(
        m_class_name         v_app_conn_registry.class_name%TYPE,
        m_class_version      v_app_conn_registry.class_version%TYPE,
        m_class_instance OUT v_app_conn_registry.class_instance%TYPE,
        m_connections    OUT v_app_conn_registry.connections%TYPE );

    PROCEDURE p_set_class_conns(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_class_version  v_app_conn_registry.class_version%TYPE,
        m_class_instance v_app_conn_registry.class_instance%TYPE,
        m_connections    v_app_conn_registry.connections%TYPE );

    FUNCTION f_get_crypt_conns(
        class_instance  v_app_conn_registry.class_instance%TYPE )
    RETURN RAW;

END appsec_only_pkg;
/

CREATE OR REPLACE PACKAGE BODY appsec.appsec_only_pkg IS

    FUNCTION f_is_cur_cached_cd(
        just_os_user     VARCHAR2,
        m_application_id v_two_fact_cd_cache.application_id%TYPE,
        m_two_factor_cd  v_two_fact_cd_cache.two_factor_cd%TYPE )
    RETURN VARCHAR2
    AS
        return_char          VARCHAR2(1) := 'N';
        cache_timeout_mins   NUMBER := 10; -- Know where to find this
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
                'app_sec_pkg.p_get_emp_2fact_nos' );
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
        SELECT class_instance, connections
        INTO m_class_instance, m_connections
        FROM v_app_conn_registry
        WHERE class_name = m_class_name
        AND class_version = m_class_version;
    END p_get_class_conns;

    PROCEDURE p_set_class_conns(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_class_version  v_app_conn_registry.class_version%TYPE,
        m_class_instance v_app_conn_registry.class_instance%TYPE,
        m_connections    v_app_conn_registry.connections%TYPE )
    IS
        v_count INTEGER;
    BEGIN
        SELECT COUNT(*) INTO v_count
            FROM v_app_conn_registry
            WHERE class_name = m_class_name
            AND class_version = m_class_version;
        IF v_count = 0 THEN
            INSERT INTO v_app_conn_registry ( class_name, class_version,
                class_instance, connections ) VALUES
                ( m_class_name, m_class_version, m_class_instance, m_connections );
        ELSE
            UPDATE v_app_conn_registry SET class_instance = m_class_instance,
                connections = m_connections, update_dt = SYSDATE
            WHERE class_name = m_class_name
            AND class_version = m_class_version;
        END IF;
    END p_set_class_conns;

    FUNCTION f_get_crypt_conns(
        class_instance  v_app_conn_registry.class_instance%TYPE )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptConns( oracle.sql.RAW ) return oracle.sql.RAW';

END appsec_only_pkg;
/

-- Procedure used to verify access to Secure Application Role
-- This was initially defined in Chapter 2 - redefined in Chapters 8, 9 and here
-- Now this procedure takes 3 arguments, as shown!
-- Not adding this to package -- this is granted execute to PUBLIC.
CREATE OR REPLACE PROCEDURE appsec.p_check_role_access(
    --m_two_factor_cd      v_two_fact_cd_cache.two_factor_cd%TYPE,
    m_application_id     v_two_fact_cd_cache.application_id%TYPE,
    m_err_no         OUT NUMBER,
    m_err_txt        OUT VARCHAR2 )
AUTHID CURRENT_USER
AS
    return_user VARCHAR2(40);
    m_app_user  v_application_registry.app_user%TYPE;
    m_app_role  v_application_registry.app_role%TYPE;
BEGIN
    m_err_no    := 0;
    m_app_user  := SYS_CONTEXT('USERENV','PROXY_USER');
    m_app_role  := appsec_only_pkg.f_get_app_role( m_application_id, m_app_user );
    return_user := f_is_sso( m_app_user );
    IF( return_user IS NOT NULL )
    THEN
    -- Code for 2-Factor Auth moved to appver Login process
    --    IF( m_two_factor_cd IS NULL OR m_two_factor_cd = '' )
    --    THEN
    --        m_err_txt := appsec_only_pkg.f_send_2_factor( return_user, m_application_id );
    --    ELSIF( appsec_only_pkg.f_is_cur_cached_cd( return_user, m_application_id, m_two_factor_cd )
    --        = 'Y' )
    --    THEN
            EXECUTE IMMEDIATE 'SET ROLE ' || m_app_role;
    --    ELSE
    --        RAISE NO_DATA_FOUND;
    --    END IF;
        app_sec_pkg.p_log_error( 0, 'Success getting SSO and setting role, ' ||
            SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    ELSE
        app_sec_pkg.p_log_error( 0, 'Problem getting SSO, ' ||
            SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        m_err_no := SQLCODE;
        m_err_txt := SQLERRM;
        app_sec_pkg.p_log_error( m_err_no, m_err_txt,
            'APPSEC p_check_role_access' );
END p_check_role_access;
/

-- Called from APPVER schema logon trigger
CREATE OR REPLACE PROCEDURE appsec.p_appver_logon
AUTHID CURRENT_USER
AS
    just_os_user    VARCHAR2(40);
    backslash_place NUMBER;
BEGIN
    just_os_user := UPPER( SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    backslash_place := INSTR( just_os_user, '\', -1 );
    IF( backslash_place > 0 )
    THEN
        just_os_user := SUBSTR( just_os_user, backslash_place + 1 );
    END IF;
    -- For logon trigger - limited SSO, no PROXY_USER and no CLIENT_IDENTIFIER
    IF( SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) = 'APPVER'
    AND( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    -- Requirements must be applicable to all applications - time may not be
    --AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    -- Assure that OS_USER is a database user
    AND( appsec_only_pkg.f_is_user( just_os_user ) = 'Y' ) )
    THEN
        app_sec_pkg.p_log_error( 0, 'Success APPVER logon, ' || just_os_user );
    ELSE
        app_sec_pkg.p_log_error( 0, 'Problem getting APPVER logon, ' || just_os_user );
        --just_os_user := sys.f_get_off;
        -- This causes logon trigger to fail -- so not connected to Oracle
        RAISE_APPLICATION_ERROR(-20003,'You are not allowed to connect to the database');
    END IF;
END p_appver_logon;
/

GRANT EXECUTE ON appsec.p_check_role_access TO PUBLIC;
GRANT EXECUTE ON appsec.p_appver_logon TO PUBLIC;

CREATE OR REPLACE PACKAGE appsec.appsec_public_pkg IS

    FUNCTION f_set_decrypt_conns( class_instance RAW, connections RAW )
    RETURN VARCHAR2;

    PROCEDURE p_get_app_conns(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        m_two_factor_cd           v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_class_instance          v_app_conn_registry.class_instance%TYPE,
        -- Either of following works as out
        m_crypt_connections   OUT v_app_conn_registry.connections%TYPE,
        --m_crypt_connections   OUT RAW,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_application_id          v_two_fact_cd_cache.application_id%TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

END appsec_public_pkg;
/

CREATE OR REPLACE PACKAGE BODY appsec.appsec_public_pkg IS

    FUNCTION f_set_decrypt_conns(
        class_instance RAW, connections RAW )
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.setDecryptConns( oracle.sql.RAW, oracle.sql.RAW ) return java.lang.String';

    PROCEDURE p_get_app_conns(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        m_two_factor_cd           v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_class_instance          v_app_conn_registry.class_instance%TYPE,
        -- Either of following works as out, first is BLOB
        m_crypt_connections   OUT v_app_conn_registry.connections%TYPE,
        --m_crypt_connections   OUT RAW,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_application_id          v_two_fact_cd_cache.application_id%TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 )
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
            ELSIF( appsec_only_pkg.f_is_cur_cached_cd( return_user, m_application_id, 
                m_two_factor_cd ) = 'Y' )
            THEN
                secret_pass_salt :=
                    app_sec_pkg.f_get_crypt_secret_salt( ext_modulus, ext_exponent );
                secret_pass_count :=
                    app_sec_pkg.f_get_crypt_secret_count( ext_modulus, ext_exponent );
                secret_pass :=
                    app_sec_pkg.f_get_crypt_secret_pass( ext_modulus, ext_exponent );
                secret_pass_algorithm :=
                    app_sec_pkg.f_get_crypt_secret_algorithm(ext_modulus, ext_exponent);
                m_crypt_connections := appsec_only_pkg.f_get_crypt_conns( m_class_instance );
            ELSE
                -- Wrong 2-Factor code entered
                RAISE NO_DATA_FOUND;
            END IF;
            app_sec_pkg.p_log_error( 0, 'Success getting App Conns, ' || return_user );
        ELSE
            app_sec_pkg.p_log_error( 0, 'Problem getting App Conns, ' || return_user );
        END IF;
    -- Raise Exceptions
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'appsec_public_pkg.p_get_app_conns' );
    END p_get_app_conns;

END appsec_public_pkg;
/

GRANT EXECUTE ON appsec.appsec_public_pkg TO PUBLIC;

-- BLOBs are tightly coupled to either the database or the Connection
-- Passing BLOBs through conduit procedures loses the coupling with the origin
-- So for now, pass Objects as RAW - Also limited to 32K
-- Should need to pass larger Objects arise, may pass BLOBs
-- With intermediate storage in database
-- //rtrnBlob = BLOB.getEmptyBLOB();
-- //rtrnBlob = (BLOB)conn.createBlob();
-- //rtrnBlob = BLOB.createTemporary( conn, false, BLOB.DURATION_SESSION );

SELECT * FROM SYS.ALL_OBJECTS
WHERE OBJECT_TYPE = 'JAVA CLASS'
AND OWNER = 'APPSEC';

