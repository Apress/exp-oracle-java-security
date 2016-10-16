-- Chapter11/apver/NewSys.sql
-- Copyright 2011, David Coffin
-- Modify IP Addresses in f_is_sso and p_appver_logon
-- Replace OSUSER with your OS UserID
-- Replace osadmin (2 places) with your OS UserID or other admin user ID
-- If you use the same OS user ID for both OSUSER and OSADMIN,
--  only create the user once
-- Replace the placeholder passwords with a real, complex passwords

-- Connect as SYS using the SYSDBA "super" system privilege
-- Perhaps using TOAD
-- or sqlplus sys@apver as sysdba
-- On apver instance!
--CONNECT sys AS sysdba;

CREATE ROLE create_session_role NOT IDENTIFIED;
GRANT CREATE SESSION TO create_session_role;

-- Give a very strong password to the appsec user!!!
GRANT create_session_role TO appsec IDENTIFIED BY password;

ALTER USER appsec DEFAULT TABLESPACE USERS QUOTA 10M ON USERS;

-- Must grant to user, not role since roles not exist without session
-- This is used in MASK / UNMASK - not needed on apver instance
GRANT EXECUTE ON sys.dbms_crypto TO appsec;

CREATE ROLE appsec_role NOT IDENTIFIED;
-- Give Application Security privilege to create Database Link
GRANT CREATE DATABASE LINK TO appsec_role;
GRANT appsec_role TO appsec;
-- Make the APPSEC_ROLE a non-default role for the APPSEC user
ALTER USER appsec DEFAULT ROLE ALL EXCEPT appsec_role;

-------------------------------------------------------------------------------
-- Switch over to APPSEC session to create link before defining APPSEC_ONLY_PKG
-------------------------------------------------------------------------------

ALTER USER appsec PASSWORD EXPIRE;

BEGIN
  DBMS_NETWORK_ACL_ADMIN.CREATE_ACL (
    acl          => 'smtp_acl_file.xml',
    description  => 'Using SMTP server',
    principal    => 'APPSEC',
    is_grant     => TRUE,
    privilege    => 'connect',
    start_date   => SYSTIMESTAMP,
    end_date     => NULL);

  COMMIT;
END;
/

BEGIN
  DBMS_NETWORK_ACL_ADMIN.ASSIGN_ACL (
    acl         => 'smtp_acl_file.xml',
    host        => 'smtp.org.com',
    lower_port  => 25,
    upper_port  => NULL);
  COMMIT;
END;
/

-- These grants are to a single user
-- Use the APPSEC account to send e-mail and open ports (HTTP)
-- NOTE: Very narrow grants - only what's needed, no more
CALL DBMS_JAVA.GRANT_PERMISSION(
    'APPSEC',
    'java.net.SocketPermission',
    'www.org.com:80',
    'connect, resolve'
);

-- Don't depend on role to get access from stored procedures
GRANT SELECT ON sys.all_users TO appsec;
--GRANT SELECT ON sys.all_source TO appsec;

REVOKE SELECT ON sys.all_users FROM PUBLIC;
REVOKE SELECT ON sys.all_source FROM PUBLIC;
REVOKE SELECT ON sys.all_source_ae FROM PUBLIC;
REVOKE SELECT ON sys.all_triggers FROM PUBLIC;
REVOKE SELECT ON sys.all_views FROM PUBLIC;
REVOKE SELECT ON sys.all_views_ae FROM PUBLIC;

----------------------------------------------------------------------
----------------------------------------------------------------------

CREATE TABLE appsec.t_appsec_errors (
    err_no     NUMBER,
    err_txt    VARCHAR2(2000),
    msg_txt    VARCHAR2(4000) DEFAULT NULL,
    update_ts  DATE DEFAULT SYSDATE
);

CREATE INDEX i_appsec_errors00 ON appsec.t_appsec_errors (
       update_ts
);

CREATE OR REPLACE VIEW appsec.v_appsec_errors AS SELECT * FROM appsec.t_appsec_errors;

CREATE TABLE appsec.t_appsec_errors_maint (
    update_ts DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX appsec.i_appsec_errors_maint00 ON appsec.t_appsec_errors_maint (
       update_ts
);

CREATE OR REPLACE PACKAGE appsec.app_sec_pkg IS

    PROCEDURE p_log_error( m_err_no NUMBER, m_err_txt VARCHAR2,
        m_msg_txt VARCHAR2 DEFAULT NULL );

    FUNCTION f_get_crypt_secret_pass( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 ) RETURN RAW;

    FUNCTION f_get_crypt_secret_algorithm( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 ) RETURN RAW;

    FUNCTION f_get_crypt_secret_salt( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 ) RETURN RAW;

    FUNCTION f_get_crypt_secret_count( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 ) RETURN RAW;

    FUNCTION f_get_crypt_data( clear_text VARCHAR2 ) RETURN RAW;

    FUNCTION f_get_decrypt_data( crypt_data RAW ) RETURN VARCHAR2;

END app_sec_pkg;
/

CREATE OR REPLACE PACKAGE BODY appsec.app_sec_pkg IS

    PROCEDURE p_log_error( m_err_no NUMBER, m_err_txt VARCHAR2,
        m_msg_txt VARCHAR2 DEFAULT NULL )
    IS
        l_err_txt VARCHAR2(2000);
    BEGIN
        l_err_txt := RTRIM( SUBSTR( m_err_txt, 1, 2000 ) );
        INSERT INTO v_appsec_errors ( err_no, err_txt, msg_txt )
            VALUES ( m_err_no, l_err_txt, m_msg_txt );
        COMMIT;
    END p_log_error;

    FUNCTION f_get_crypt_secret_pass( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptSessionSecretDESPassPhrase( java.lang.String, java.lang.String ) return oracle.sql.RAW';

    FUNCTION f_get_crypt_secret_algorithm( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptSessionSecretDESAlgorithm( java.lang.String, java.lang.String ) return oracle.sql.RAW';

    FUNCTION f_get_crypt_secret_salt( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptSessionSecretDESSalt( java.lang.String, java.lang.String ) return oracle.sql.RAW';

    FUNCTION f_get_crypt_secret_count( ext_modulus VARCHAR2,
        ext_exponent VARCHAR2 )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptSessionSecretDESIterationCount( java.lang.String, java.lang.String ) return oracle.sql.RAW';

    FUNCTION f_get_crypt_data( clear_text VARCHAR2 )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptData( java.lang.String ) return oracle.sql.RAW';

    FUNCTION f_get_decrypt_data( crypt_data RAW )
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getDecryptData( oracle.sql.RAW ) return java.lang.String';

END app_sec_pkg;
/

CREATE OR REPLACE PROCEDURE appsec.p_appsec_errors_janitor
AS
    PRAGMA AUTONOMOUS_TRANSACTION;
    m_err_no NUMBER;
    m_err_txt VARCHAR2(2000);
BEGIN
    INSERT INTO t_appsec_errors_maint ( update_ts ) VALUES ( SYSDATE );
    COMMIT;
    -- Remove error log entries over 45 days old
    DELETE FROM t_appsec_errors WHERE update_ts < ( SYSDATE - 45 );
    COMMIT;
    INSERT INTO t_appsec_errors
        ( err_no, err_txt, msg_txt ) VALUES
        ( 0, 'No Error', 'Success managing log file by Janitor' );
    COMMIT;
EXCEPTION
    WHEN OTHERS
    THEN
        m_err_no := SQLCODE;
        m_err_txt := SQLERRM;
        INSERT INTO t_appsec_errors
            ( err_no, err_txt, msg_txt ) VALUES
            ( m_err_no, m_err_txt, 'Error managing log file by Janitor' );
        COMMIT;
END;
/

CREATE OR REPLACE TRIGGER appsec.t_appsec_errors_iar
    AFTER INSERT ON appsec.t_appsec_errors FOR EACH ROW
DECLARE
    m_log_maint_dt DATE;
BEGIN
    SELECT MAX( update_ts ) INTO m_log_maint_dt FROM appsec.t_appsec_errors_maint;
    -- Whenever T_APPSEC_ERRORS_MAINT is empty, M_LOG_MAINT_DT is null
    IF( ( m_log_maint_dt IS NULL ) OR
        ( m_log_maint_dt < ( SYSDATE - 1 ) ) )
    THEN
        appsec.p_appsec_errors_janitor;
    END IF;
END;
/

ALTER TRIGGER appsec.t_appsec_errors_iar ENABLE;

CREATE TABLE appsec.t_two_fact_cd_cache
(
    employee_id    NUMBER(6) NOT NULL,
    application_id VARCHAR2(24 BYTE) NOT NULL,
    two_factor_cd  VARCHAR2(24 BYTE),
    ip_address     VARCHAR2(45 BYTE) DEFAULT SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ),
    distrib_cd     NUMBER(1),
    cache_ts       DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX appsec.two_fact_cd_emp_id_pk ON appsec.t_two_fact_cd_cache
    (employee_id,application_id);

ALTER TABLE appsec.t_two_fact_cd_cache ADD (
    CONSTRAINT two_fact_cd_emp_id_pk
    PRIMARY KEY
    (employee_id,application_id)
    USING INDEX appsec.two_fact_cd_emp_id_pk
);

CREATE OR REPLACE VIEW appsec.v_two_fact_cd_cache AS SELECT * FROM appsec.t_two_fact_cd_cache;

CREATE PROFILE appver_prof LIMIT
    CONNECT_TIME          1
    IDLE_TIME             1
    SESSIONS_PER_USER     UNLIMITED
    PASSWORD_LIFE_TIME    UNLIMITED
    FAILED_LOGIN_ATTEMPTS UNLIMITED;

-- Go ahead and assign a password - this is one password that we use more like
-- an address.  It can be embedded into applications but is only useful for
-- application verification (identify an application to get access to resources)
CREATE USER appver
    IDENTIFIED BY password
    QUOTA 0 ON SYSTEM
    PROFILE appver_prof;

GRANT create_session_role TO appver;

-- Do this for each operating system user -- do it now for your account
CREATE USER osuser IDENTIFIED EXTERNALLY;
GRANT create_session_role TO osuser;
ALTER USER osuser GRANT CONNECT THROUGH appver;

CREATE USER osadmin IDENTIFIED EXTERNALLY;
GRANT create_session_role TO osadmin;
ALTER USER osadmin GRANT CONNECT THROUGH appver;

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
    USING INDEX appsec.application_registry_pk
);

CREATE OR REPLACE VIEW appsec.v_application_registry AS SELECT * FROM appsec.t_application_registry;

INSERT INTO appsec.v_application_registry
( application_id, app_user, app_role )
VALUES
( 'HRVIEW', 'APPUSR', 'HRVIEW_ROLE' );

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

CREATE UNIQUE INDEX appsec.app_conn_registry_nam_ver_pk ON appsec.t_app_conn_registry
    (class_name, class_version);

ALTER TABLE appsec.t_app_conn_registry ADD (
    CONSTRAINT app_conn_registry_nam_ver_pk
    PRIMARY KEY
    (class_name, class_version)
    USING INDEX appsec.app_conn_registry_nam_ver_pk
);

CREATE OR REPLACE VIEW appsec.v_app_conn_registry AS SELECT * FROM appsec.t_app_conn_registry;


-- Possibly store keys table on separate database and select accross a link
-- That way, separately backed up
CREATE TABLE appsec.t_application_key
(
    key_version NUMBER(3) NOT NULL,
    -- Max Key size 1024 bits (128 Bytes)
    key_bytes   RAW(128) NOT NULL,
    create_ts   DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX appsec.application_key_pk ON appsec.t_application_key
    (key_version);

ALTER TABLE appsec.t_application_key ADD (
    CONSTRAINT application_key_pk
    PRIMARY KEY
    (key_version)
    USING INDEX appsec.application_key_pk
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

COMMIT;


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
        -- Reference to type across database links not going to work
        -- at least not from SYS configuring procedure in APPSEC using APSEC link
        --os_user               hr.v_emp_mobile_nos.user_id%TYPE,
        os_user               VARCHAR2,
        fmt_string            VARCHAR2,
        m_employee_id     OUT NUMBER,
        m_com_pager_no    OUT VARCHAR2,
        m_sms_phone_no    OUT VARCHAR2,
        m_sms_carrier_url OUT VARCHAR2,
        m_email           OUT VARCHAR2,
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
        --FROM v_two_fact_cd_cache c, hr.v_emp_mobile_nos m
        FROM v_two_fact_cd_cache c, hr.v_emp_mobile_nos@orcl_link m
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
        -- Reference to type across database links not going to work
        -- at least not from SYS configuring procedure in APPSEC using APSEC link
        --os_user               hr.v_emp_mobile_nos.user_id%TYPE,
        os_user               VARCHAR2,
        fmt_string            VARCHAR2,
        m_employee_id     OUT NUMBER,
        m_com_pager_no    OUT VARCHAR2,
        m_sms_phone_no    OUT VARCHAR2,
        m_sms_carrier_url OUT VARCHAR2,
        m_email           OUT VARCHAR2,
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
        --FROM hr.v_emp_mobile_nos m, hr.v_employees_public e,
        --    hr.v_sms_carrier_host s, v_two_fact_cd_cache c
        FROM hr.v_emp_mobile_nos@orcl_link m, hr.v_employees_public@orcl_link e,
            hr.v_sms_carrier_host@orcl_link s, v_two_fact_cd_cache c
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

-- Procedure used to verify access to Secure Application Role
-- This was initially defined in Chapter 2 - redefined in Chapters 8, 9 and here
-- Now this procedure takes 3 arguments (previously 4 arguments )!
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
        EXECUTE IMMEDIATE 'SET ROLE ' || m_app_role;
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

-- Create APPSEC.P_APPVER_LOGON procedure before this
-- T_CHECK_APPVER_ACCESS is a logon trigger, only for the APPVER user
-- On orcl instance in secadm schema, on apver in appsec schema
CREATE OR REPLACE TRIGGER appsec.t_screen_appver_access AFTER LOGON ON appver.SCHEMA
BEGIN
    appsec.p_appver_logon;
END;
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

-- Will be used to manage Application Verification Data
CREATE ROLE appver_admin NOT IDENTIFIED;

GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_admin;

-- Grant APPVER_ADMIN role to each user who is allowed to update / copy connection strings
GRANT appver_admin TO osadmin;

-- Remove F_SET_DECRYPT_CONNS in Chapter 11
CREATE OR REPLACE PACKAGE appsec.appsec_public_pkg IS

    PROCEDURE p_get_app_conns(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        m_two_factor_cd           v_two_fact_cd_cache.two_factor_cd%TYPE,
        m_class_instance          v_app_conn_registry.class_instance%TYPE,
        m_crypt_connections   out v_app_conn_registry.connections%TYPE,
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

GRANT EXECUTE ON appsec.appsec_public_pkg TO PUBLIC;

-- Use the same wrapped versions of F_MASK and F_UNMASK that you created earlier
CREATE OR REPLACE FUNCTION appsec.f_mask wrapped
a000000
b2
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
8
3d9 237
GehnTGWDxAhWnsVg2jYOTJ2/sF4wg/BeTCCsfI5Vgp0GvFbmFJFF9PpfKGM8NUbmI21KsMmT
9YLZz1gSTsZkw/skypO3G2z+bhL/AGJObl6IY3bf/PjNwdlhZ5argmaJytVX0RDALqjMIRvj
GLdGjZoM6cJZs4nHbLQMRgmOh9ZTnOnU0fQMG0vDHhtBL0CZSmx1R0SWpFQ20Iui96EL3CD4
Ulczxst6rjfBUnp/48INSF46be/yl/M9rJRBGZzT7Dp3UPW+t2+O8WuopAiz0+zPije7Wdhn
chUu85NHTUbsW/Oc3mJ/H97ACuEKyL05F284o7LH3swT1OHtcdQBL4cvoYHsnpjlLIJ43/9p
iQ7DZWJyMz0QdssA5FV+YbsFgUgsZL8s+HJBHdwKfVZaaVgMWu3IcLRNYadcZf0y9eXwY3EH
uDywFa0yUOp0Rx1zkYqq0JO81DyITDC4OI/q8tcFJ4inUsdLE5qGZcFv2GZ0B+8sknimq/Hj
1atpfb/f+oVZAZkY78T0YBdSmyOSgifZtm0IiEdc5rh/Lbn5pmTzHV8=

/

CREATE OR REPLACE FUNCTION appsec.f_unmask wrapped
a000000
b2
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
8
3dd 23f
ovTsGtbAu4QyKt+xvxm1SXnNkoEwg/BeLvYVZy/NrZ3g0ZU2bMO6lKt6ft/2shsTSwOzi6CJ
UTuJIyYZkoaYMXWWJA6ZmbaL7Vh4lgNOX16IG3Zh/FO1P/g6wmJQBxh6jfLIKomAgB2345Tw
51EGFMmV/vL3IVwh7nG9M9NRjr4FyrkBQcLRUpU2b3NItq7nakTG01nJrB+eVqxjU+PzONsp
9iRK6LcmHXKCj5OOQjnMiTwBxRDMWqF/GqPCaD3EBeaCT6vs3JoaOr6REVpsInE1htAAbldB
Qx6TU6FmbQSNaU7KXWUmukfp0w+fN4GsvTli9HwKQCnyd1F/gHi3zDhGHgcJ7RsV4ptjwWBg
mem98my3ZmFy+ca7ICjQBc25EMQxLFHX+YalMcfdvoMhpQvDyYTTvzW4s/Xt7CtSfLzMJm+n
uHnmCtwCxyeMcgR1OiMBiqrQk36GPYhbpXyp7hr8d4o8jTgdyeGYQhxMTwVU1AwvOFerrg6q
+w6Z08DpEJ5zE+kJ0031oVJ6Edizh26gQYdgYjEDBChw4mUctnEjPFUs1RI2VQ==

/

