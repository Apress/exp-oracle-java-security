-- Chapter7/AppPkgTemplate.sql
-- Copyright 2011, David Coffin

-- In the following procedures
-- Replace APPSCHEMA with your app schema name
-- Replace APPTABLE with the name of a sensitive table whose data you protect
-- Replace COLUMNx with your table column names
-- Replace SENS_COLUMNx with names of your sensitive columns
-- Replace APPSCHEMA_SEC_PKG with the name of your security package

-- App Developer -- your schema needs CREATE PROCEDURE system privilege
-- Request execute on Application Security package from Security Administrator
-- GRANT EXECUTE ON appsec.app_sec_pkg TO APPSCHEMA;
-- Also give permission for your App Users to execute your app security package
-- GRANT EXECUTE ON APPSCHEMA.APPSCHEMA_SEC_PKG TO APPSCHEMA_USERS;

CREATE OR REPLACE PACKAGE APPSCHEMA_SEC_PKG IS

    TYPE RESULTSET_TYPE IS REF CURSOR;

    PROCEDURE p_get_shared_passphrase(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    PROCEDURE p_select_APPTABLE_sensitive(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    PROCEDURE p_select_APPTABLE_by_COLUMN1_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_COLUMN1                 APPTABLE.COLUMN1%TYPE );

    PROCEDURE p_update_APPTABLE_sensitive(
        m_COLUMN1          APPTABLE.COLUMN1%TYPE,
        m_COLUMN2          APPTABLE.COLUMN2%TYPE,
        m_COLUMN3          APPTABLE.COLUMN3%TYPE,
        m_COLUMN4          APPTABLE.COLUMN4%TYPE,
        crypt_sens_COLUMN5 RAW,
        crypt_sens_COLUMN6 RAW,
        m_err_no       OUT NUMBER,
        m_err_txt      OUT VARCHAR2 );

END APPSCHEMA_SEC_PKG;
/

CREATE OR REPLACE PACKAGE BODY APPSCHEMA_SEC_PKG IS

    PROCEDURE p_get_shared_passphrase(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 )
    IS BEGIN
        m_err_no := 0;
        secret_pass_salt :=
            appsec.app_sec_pkg.f_get_crypt_secret_salt( ext_modulus, ext_exponent );
        secret_pass_count :=
            appsec.app_sec_pkg.f_get_crypt_secret_count( ext_modulus, ext_exponent );
        secret_pass :=
            appsec.app_sec_pkg.f_get_crypt_secret_pass( ext_modulus, ext_exponent );
        secret_pass_algorithm :=
            appsec.app_sec_pkg.f_get_crypt_secret_algorithm( ext_modulus, ext_exponent );
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'APPSCHEMA p_get_shared_passphrase' );
    END p_get_shared_passphrase;

    PROCEDURE p_select_APPTABLE_sensitive(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 )
    IS BEGIN
        m_err_no := 0;
        secret_pass_salt :=
            appsec.app_sec_pkg.f_get_crypt_secret_salt( ext_modulus, ext_exponent );
        secret_pass_count :=
            appsec.app_sec_pkg.f_get_crypt_secret_count( ext_modulus, ext_exponent );
        secret_pass :=
            appsec.app_sec_pkg.f_get_crypt_secret_pass( ext_modulus, ext_exponent );
        secret_pass_algorithm :=
            appsec.app_sec_pkg.f_get_crypt_secret_algorithm( ext_modulus, ext_exponent );
        OPEN resultset_out FOR SELECT
            COLUMN1,
            COLUMN2,
            COLUMN3,
            COLUMN4,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( COLUMN5 ) ),
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( COLUMN6 ) )
        FROM APPTABLE;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'APPSCHEMA p_select_APPTABLE_sensitive' );
    END p_select_APPTABLE_sensitive;

    PROCEDURE p_select_APPTABLE_by_COLUMN1_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_COLUMN1                 APPTABLE.COLUMN1%TYPE );
    IS BEGIN
        m_err_no := 0;
        secret_pass_salt :=
            appsec.app_sec_pkg.f_get_crypt_secret_salt( ext_modulus, ext_exponent );
        secret_pass_count :=
            appsec.app_sec_pkg.f_get_crypt_secret_count( ext_modulus, ext_exponent );
        secret_pass :=
            appsec.app_sec_pkg.f_get_crypt_secret_pass( ext_modulus, ext_exponent );
        secret_pass_algorithm :=
            appsec.app_sec_pkg.f_get_crypt_secret_algorithm( ext_modulus, ext_exponent );
        OPEN resultset_out FOR SELECT
            COLUMN1,
            COLUMN2,
            COLUMN3,
            COLUMN4,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( COLUMN5 ) ),
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( COLUMN6 ) )
        FROM APPTABLE
        WHERE COLUMN1 = m_COLUMN1;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'APPSCHEMA p_select_APPTABLE_by_COLUMN1_sens' );
    END p_select_APPTABLE_by_COLUMN1_sens;

    -- Note:  Use of this procedure assumes you have already done a select
    -- or that you have already called P_GET_SHARED_PASSPHRASE
    -- and that you are using the same Session Secret PassPhrase
    PROCEDURE p_update_APPTABLE_sensitive(
        m_COLUMN1          APPTABLE.COLUMN1%TYPE,
        m_COLUMN2          APPTABLE.COLUMN2%TYPE,
        m_COLUMN3          APPTABLE.COLUMN3%TYPE,
        m_COLUMN4          APPTABLE.COLUMN4%TYPE,
        crypt_sens_COLUMN5 RAW,
        crypt_sens_COLUMN6 RAW,
        m_err_no       OUT NUMBER,
        m_err_txt      OUT VARCHAR2 )
    IS
        test_row_ct       NUMBER(6);
        v_COLUMN5         VARCHAR2(15); -- set size appropriately
        v_COLUMN6         VARCHAR2(15);
    BEGIN
        m_err_no := 0;
        v_COLUMN5 := appsec.app_sec_pkg.f_get_decrypt_data( crypt_sens_COLUMN5 );
        v_COLUMN6 := appsec.app_sec_pkg.f_get_decrypt_data( crypt_sens_COLUMN6 );
        SELECT COUNT(*) INTO test_row_ct FROM APPTABLE WHERE
            COLUMN1 = m_COLUMN1;
        IF test_row_ct = 0
        THEN
            INSERT INTO APPTABLE
                (COLUMN1, COLUMN2, COLUMN3, COLUMN4, COLUMN5, COLUMN6)
            VALUES
                (m_COLUMN1, m_COLUMN2, m_COLUMN3, m_COLUMN4, v_COLUMN5, v_COLUMN6);
        ELSE
            UPDATE APPTABLE
            SET COLUMN2 = m_COLUMN2, COLUMN3 = m_COLUMN3,
                COLUMN4 = m_COLUMN4, COLUMN5 = v_COLUMN5, COLUMN6 = v_COLUMN6
            WHERE COLUMN1 = m_COLUMN1;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'APPSCHEMA p_update_APPTABLE_sensitive' );
    END p_update_APPTABLE_sensitive;

END APPSCHEMA_SEC_PKG;
/
