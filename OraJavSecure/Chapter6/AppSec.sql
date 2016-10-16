-- Chapter6/AppSec.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appsec;

-- Enable the non-default role needed in order to create procedures
SET ROLE appsec_role;

CREATE OR REPLACE PACKAGE appsec.app_sec_pkg IS

    -- For Chapter 6 testing only - move to app in later versions of this package
    PROCEDURE p_get_shared_passphrase(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    -- For Chapter 6 testing only - remove in later versions of this package
    PROCEDURE p_get_des_crypt_test_data(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        test_data                 VARCHAR2,
        crypt_data            OUT RAW );

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

    -- For Chapter 6 testing only - remove in later versions of this package
    FUNCTION f_show_algorithm RETURN VARCHAR2;

END app_sec_pkg;
/

CREATE OR REPLACE PACKAGE BODY appsec.app_sec_pkg IS

    -- For Chapter 6 testing only - move to app in later versions of this package
    PROCEDURE p_get_shared_passphrase(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 )
    IS BEGIN
        m_err_no := 0;
        secret_pass_salt := f_get_crypt_secret_salt( ext_modulus, ext_exponent );
        secret_pass_count := f_get_crypt_secret_count( ext_modulus, ext_exponent );
        secret_pass := f_get_crypt_secret_pass( ext_modulus, ext_exponent );
        secret_pass_algorithm :=
            f_get_crypt_secret_algorithm( ext_modulus, ext_exponent );
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
    END p_get_shared_passphrase;

    -- For Chapter 6 testing only - remove in later versions of this package
    PROCEDURE p_get_des_crypt_test_data(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        test_data                 VARCHAR2,
        crypt_data            OUT RAW )
    IS BEGIN
        m_err_no := 0;
        secret_pass_salt := f_get_crypt_secret_salt( ext_modulus, ext_exponent );
        secret_pass_count := f_get_crypt_secret_count( ext_modulus, ext_exponent );
        secret_pass := f_get_crypt_secret_pass( ext_modulus, ext_exponent );
        secret_pass_algorithm :=
            f_get_crypt_secret_algorithm( ext_modulus, ext_exponent );
        crypt_data := f_get_crypt_data( test_data );
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
    END p_get_des_crypt_test_data;

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

    -- For Chapter 6 testing only - remove in later versions of this package
    FUNCTION f_show_algorithm 
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.showAlgorithm() return java.lang.String';

END app_sec_pkg;
/
