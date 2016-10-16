-- Chapter7/AppSec.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appsec;

-- Enable the non-default role needed in order to create procedures
SET ROLE appsec_role;

-- You will want to be dilligent in configuring the tables
-- for expected size and growth, and establish old log purging schedule
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

CREATE UNIQUE INDEX i_appsec_errors_maint00 ON appsec.t_appsec_errors_maint (
       update_ts
);

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
    AFTER INSERT ON t_appsec_errors FOR EACH ROW
DECLARE
    m_log_maint_dt DATE;
BEGIN
    SELECT MAX( update_ts ) INTO m_log_maint_dt FROM t_appsec_errors_maint;
    -- Whenever T_APPSEC_ERRORS_MAINT is empty, M_LOG_MAINT_DT is null
    IF( ( m_log_maint_dt IS NULL ) OR
        ( m_log_maint_dt < ( SYSDATE - 1 ) ) )
    THEN
        p_appsec_errors_janitor;
    END IF;
END;
/

ALTER TRIGGER appsec.t_appsec_errors_iar ENABLE;

--DELETE FROM v_appsec_errors;
--DELETE FROM t_appsec_errors_maint;
-- Insert a log record
INSERT INTO appsec.v_appsec_errors (err_no, err_txt ) VALUES (1, 'DAVE' );
COMMIT;
-- Observe log janitor was run
SELECT * FROM appsec.v_appsec_errors ORDER BY update_ts;
SELECT * FROM appsec.t_appsec_errors_maint ORDER BY update_ts;
-- Insert another log record - over 45 days old
INSERT INTO appsec.v_appsec_errors (err_no, err_txt, msg_txt, update_ts)
    VALUES (2, 'DAVE', 'NONE', SYSDATE - 60 );
COMMIT;
-- Observe log janitor was NOT run a second time on same day
SELECT * FROM appsec.v_appsec_errors ORDER BY update_ts;
SELECT * FROM appsec.t_appsec_errors_maint ORDER BY update_ts;
-- Pretend the janitor has not run since yesterday
UPDATE appsec.t_appsec_errors_maint SET update_ts = SYSDATE-1;
COMMIT;
SELECT * FROM appsec.t_appsec_errors_maint ORDER BY update_ts;
-- Insert another log record
INSERT INTO appsec.v_appsec_errors (err_no, err_txt ) VALUES (3, 'DAVE' );
COMMIT;
-- Observe log janitor was run a second time
-- and it removed the old log record (the one with ERR_NO=2)
SELECT * FROM appsec.v_appsec_errors ORDER BY update_ts;
SELECT * FROM appsec.t_appsec_errors_maint ORDER BY update_ts;


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
