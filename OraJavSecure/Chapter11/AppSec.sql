-- Chapter11/AppSec.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appsec;

-- Enable non-default role
SET ROLE appsec_role;
-- Enable all default and non-default roles
SET ROLE ALL;
-- See all the roles that are granted
SELECT * FROM sys.session_roles;

-- Possibly store keys table on separate database and select across a link
-- That way, separately backed up
CREATE TABLE appsec.t_application_key
(
    key_version NUMBER(3) NOT NULL,
    -- Max Key size 1024 bits (128 Bytes)
    key_bytes   RAW(128) NOT NULL,
    create_ts   DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX application_key_pk ON appsec.t_application_key
    (key_version);

ALTER TABLE appsec.t_application_key ADD (
    CONSTRAINT application_key_pk
    PRIMARY KEY
    (key_version)
    USING INDEX application_key_pk
);

CREATE OR REPLACE VIEW appsec.v_application_key AS SELECT * FROM appsec.t_application_key;

-- Trigger to prevent updating / deleting
CREATE OR REPLACE TRIGGER appsec.t_application_key_budr BEFORE UPDATE OR DELETE
    ON appsec.t_application_key FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR( -20001, 'Cannot UPDATE or DELETE Records in V_APPLICATION_KEY.' );
END;
/

ALTER TRIGGER appsec.t_application_key_budr ENABLE;

INSERT INTO appsec.v_application_key
( key_version, key_bytes )
VALUES
( 1, SYS.DBMS_CRYPTO.RANDOMBYTES(1024/8) );
INSERT INTO appsec.v_application_key
( key_version, key_bytes )
VALUES
( 2, SYS.DBMS_CRYPTO.RANDOMBYTES(1024/8) );
INSERT INTO appsec.v_application_key
( key_version, key_bytes )
VALUES
( 3, SYS.DBMS_CRYPTO.RANDOMBYTES(1024/8) );
INSERT INTO appsec.v_application_key
( key_version, key_bytes )
VALUES
( 4, SYS.DBMS_CRYPTO.RANDOMBYTES(1024/8) );
INSERT INTO appsec.v_application_key
( key_version, key_bytes )
VALUES
( 5, SYS.DBMS_CRYPTO.RANDOMBYTES(1024/8) );


CREATE OR REPLACE PACKAGE appsec.appsec_only_pkg IS

    -- New in Chapter 11
    FUNCTION f_copy_conns( class_instance RAW, class_version VARCHAR2 )
    RETURN VARCHAR2;

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

CREATE OR REPLACE PACKAGE appsec.appsec_admin_pkg IS

    -- Move from APPSEC_PUBLIC_PKG
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

    -- Move from APPSEC_PUBLIC_PKG
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

-- As SYS
--CREATE ROLE appver_admin NOT IDENTIFIED;

GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_admin;

-- Grant APPVER_ADMIN role to each user who is allowed to update / copy connection strings
-- As SYS
--GRANT appver_admin TO osadmin;

-- Remove F_SET_DECRYPT_CONNS in Chapter 11
CREATE OR REPLACE PACKAGE appsec.appsec_public_pkg IS

    PROCEDURE p_get_app_conns(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        m_two_factor_cd           v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_class_instance          v_app_conn_registry.class_instance%TYPE,
        -- Either of following works as out
        m_crypt_connections   out v_app_conn_registry.connections%TYPE,
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

-- Remove F_SET_DECRYPT_CONNS in Chapter 11
CREATE OR REPLACE PACKAGE BODY appsec.appsec_public_pkg IS

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
            ELSIF( appsec_only_pkg.f_is_cur_cached_cd( return_user, m_application_id, m_two_factor_cd )
                = 'Y' )
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
                'p_get_app_conns' );
    END p_get_app_conns;

END appsec_public_pkg;
/

-- Already granted in Chapter 10
--GRANT EXECUTE ON appsec.appsec_public_pkg TO PUBLIC;

-- Testing XOR
-- XOR Original String with Other String, then XOR Result with Other String
-- Final Result is Original String
-- Cast as RAWs for calculation, Cast to VARCHAR2 for presentation
SELECT SYS.UTL_RAW.CAST_TO_VARCHAR2(
  SYS.UTL_RAW.BIT_XOR(
    SYS.UTL_RAW.BIT_XOR(
      SYS.UTL_RAW.CAST_TO_RAW('ThisIsString1'),
      SYS.UTL_RAW.CAST_TO_RAW('NotTheSame')
    ),
    SYS.UTL_RAW.CAST_TO_RAW('NotTheSame')
  )
)FROM DUAL;
-- ThisIsString1
