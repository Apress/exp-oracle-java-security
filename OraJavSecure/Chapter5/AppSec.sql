-- Chapter5/AppSec.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appsec;

-- Enable the non-default role needed in order to create procedures
SET ROLE appsec_role;

-- This Java Stored procedure (Function) Encrypts data with RSA public key
-- Calls method to build public key from modulus and exponent
CREATE OR REPLACE FUNCTION f_get_rsa_crypt(
    ext_rsa_mod VARCHAR2, ext_rsa_exp VARCHAR2, cleartext VARCHAR2 )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getRSACryptData( java.lang.String, java.lang.String, java.lang.String ) return oracle.sql.RAW';
/

-- This stored procedure takes public key modulus and exponent
-- And returns the server SYSDATE encrypted with RSA public key
CREATE OR REPLACE PROCEDURE p_get_rsa_crypt_sysdate(
    ext_rsa_mod    IN VARCHAR2,
    ext_rsa_exp    IN VARCHAR2,
    crypt_sysdate OUT RAW,
    m_err_no      OUT NUMBER,
    m_err_txt     OUT VARCHAR2 )
IS BEGIN
    m_err_no := 0;
    crypt_sysdate := f_get_rsa_crypt( ext_rsa_mod, ext_rsa_exp,
        TO_CHAR( CURRENT_TIMESTAMP, 'DY MON DD HH24:MI:SS TZD YYYY' ) );
EXCEPTION
    WHEN OTHERS THEN
        m_err_no := SQLCODE;
        m_err_txt := SQLERRM;
END p_get_rsa_crypt_sysdate;
/

-- Test timezone settings, if having trouble getting timezone from Oracle
SELECT TO_CHAR( CURRENT_TIMESTAMP, 'DY MON DD HH24:MI:SS TZD YYYY' ) FROM DUAL;
SELECT * FROM sys.gv_$timezone_names
    WHERE tzname LIKE 'America%' --AND tzabbrev = 'EST'
;
ALTER SESSION SET TIME_ZONE = 'America/New_York';
SELECT TO_CHAR( CURRENT_TIMESTAMP, 'DY MON DD HH24:MI:SS TZD YYYY' ) FROM DUAL;

-- To remove this test function and procedure, execute these
--DROP PROCEDURE p_get_rsa_crypt_sysdate;
--DROP FUNCTION f_get_rsa_crypt;
