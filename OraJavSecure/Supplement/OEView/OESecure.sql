-- Supplement/OEView/OE.sql
-- Copyright 2011, David Coffin

-- Requires Sample Schema installed

--CONNECT OE;

-- STEP 1: Create or Replace a view of customer data with expunged view
-- Swap null for DATE_OF_BIRTH, MARITAL_STATUS and INCOME_LEVEL
CREATE OR REPLACE FORCE VIEW OE.v_customer_detail
    AS SELECT
                customer_id,
                cust_first_name,
                cust_last_name,
                cust_address,
                phone_numbers,
                nls_language,
                nls_territory,
                credit_limit,
                cust_email,
                account_mgr_id,
                cust_geo_location,
        null    date_of_birth,
        ''      marital_status,
                gender,
        ''      income_level
    FROM OE.customers;

SELECT * FROM oe.v_customer_detail ;


-- STEP 2: Create alternate, prefered views public and sensitive
-- We will request applications already using OE.customers table
--  and v_customer_detail view to use this view instead
CREATE OR REPLACE FORCE VIEW OE.v_customer_detail_public
    AS SELECT
        customer_id,
        cust_first_name,
        cust_last_name,
        cust_address,
        phone_numbers,
        nls_language,
        nls_territory,
        credit_limit,
        cust_email,
        account_mgr_id,
        cust_geo_location,
        gender
    FROM OE.customers;

SELECT * FROM oe.v_customer_detail_public ;

GRANT SELECT ON OE.v_customer_detail_public TO oeview_role;

CREATE OR REPLACE FORCE VIEW OE.v_customer_detail_sensitive
    AS SELECT * FROM OE.customers;

SELECT * FROM oe.v_customer_detail_sensitive ;

-- No grants to v_customer_detail_sensitive, use it internally only


-- STEP 3: Create SH trigger to expunge future archive records
--  and clean existing customer archive data, see SH.sql


-- STEP 4: Provide procedures for selecting and updating OE.customers
CREATE OR REPLACE PACKAGE oe.oe_sec_pkg IS

    TYPE RESULTSET_TYPE IS REF CURSOR;

    PROCEDURE p_select_customers_sensitive(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    PROCEDURE p_update_customers_sensitive(
        m_customer_id            customers.customer_id%TYPE,
        m_cust_first_name        customers.cust_first_name%TYPE,
        m_cust_last_name         customers.cust_last_name%TYPE,
        --m_cust_address           customers.cust_address%TYPE,
        --m_phone_numbers          customers.phone_numbers%TYPE,
        --m_nls_language           customers.nls_language%TYPE,
        --m_nls_territory          customers.nls_territory%TYPE,
        m_credit_limit           customers.credit_limit%TYPE,
        m_cust_email             customers.cust_email%TYPE,
        --m_account_mgr_id         customers.account_mgr_id%TYPE,
        --m_cust_geo_location      customers.cust_geo_location%TYPE,
        crypt_date_of_birth      RAW,
        crypt_marital_status     RAW,
        m_gender                 customers.gender%TYPE,
        --crypt_income_level       RAW,
        m_err_no             OUT NUMBER,
        m_err_txt            OUT VARCHAR2 );

END oe_sec_pkg;
/

-- Grant Execute to this package only for roles who need it
CREATE OR REPLACE PACKAGE BODY oe.oe_sec_pkg IS

    PROCEDURE p_select_customers_sensitive(
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
            appsec.app_sec_pkg.f_get_crypt_secret_algorithm(ext_modulus, ext_exponent);
        OPEN resultset_out FOR SELECT
            CUSTOMER_ID,
            CUST_FIRST_NAME,
            CUST_LAST_NAME,
            CUST_ADDRESS,
            PHONE_NUMBERS,
            NLS_LANGUAGE,
            NLS_TERRITORY,
            CREDIT_LIMIT,
            CUST_EMAIL,
            ACCOUNT_MGR_ID,
            CUST_GEO_LOCATION,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( DATE_OF_BIRTH, 'MM/DD/YYYY' ) ),
            appsec.app_sec_pkg.f_get_crypt_data( MARITAL_STATUS ),
            GENDER,
            appsec.app_sec_pkg.f_get_crypt_data( INCOME_LEVEL )
        FROM OE.v_customer_detail_sensitive ORDER BY CUSTOMER_ID;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'OE p_select_customers_sensitive' );
    END p_select_customers_sensitive;

    PROCEDURE p_update_customers_sensitive(
        m_customer_id            customers.customer_id%TYPE,
        m_cust_first_name        customers.cust_first_name%TYPE,
        m_cust_last_name         customers.cust_last_name%TYPE,
        --m_cust_address           customers.cust_address%TYPE,
        --m_phone_numbers          customers.phone_numbers%TYPE,
        --m_nls_language           customers.nls_language%TYPE,
        --m_nls_territory          customers.nls_territory%TYPE,
        m_credit_limit           customers.credit_limit%TYPE,
        m_cust_email             customers.cust_email%TYPE,
        --m_account_mgr_id         customers.account_mgr_id%TYPE,
        --m_cust_geo_location      customers.cust_geo_location%TYPE,
        crypt_date_of_birth      RAW,
        crypt_marital_status     RAW,
        m_gender                 customers.gender%TYPE,
        --crypt_income_level       RAW,
        m_err_no             OUT NUMBER,
        m_err_txt            OUT VARCHAR2 )
    IS
        test_cust_ct     NUMBER(6);
        v_date_of_birth  customers.date_of_birth%TYPE;
        v_marital_status customers.marital_status%TYPE;
        v_income_level   customers.income_level%TYPE;
    BEGIN
        -- Note:  Use of this procedure assumes you have already done a select
        -- and that you are using the same Session Secret PassPhrase
        m_err_no := 0;
        v_date_of_birth := TO_DATE(
            appsec.app_sec_pkg.f_get_decrypt_data( crypt_date_of_birth ),
            'MM/DD/YYYY' );
        v_marital_status :=
            appsec.app_sec_pkg.f_get_decrypt_data( crypt_marital_status );
        --v_income_level :=
        --    appsec.app_sec_pkg.f_get_decrypt_data( crypt_income_level );
        SELECT COUNT(*) INTO test_cust_ct FROM OE.v_customer_detail_sensitive WHERE
            customer_id = m_customer_id;
        IF test_cust_ct = 0
        THEN
            -- Insert will not be called, since only updating existing
            INSERT INTO OE.v_customer_detail_sensitive
                ( CUSTOMER_ID, CUST_FIRST_NAME, CUST_LAST_NAME, CUST_ADDRESS,
                    PHONE_NUMBERS, NLS_LANGUAGE, NLS_TERRITORY, CREDIT_LIMIT,
                    CUST_EMAIL, ACCOUNT_MGR_ID, CUST_GEO_LOCATION,
                    DATE_OF_BIRTH, MARITAL_STATUS, GENDER, INCOME_LEVEL )
            VALUES
                --( m_customer_id, m_cust_first_name, m_cust_last_name, m_cust_address,
                --m_phone_numbers, m_nls_language, m_nls_territory, m_credit_limit,
                --m_cust_email, m_account_mgr_id, m_cust_geo_location,
                --v_date_of_birth, v_marital_status, m_gender, v_income_level );
                ( m_customer_id, m_cust_first_name, m_cust_last_name, null,
                null, null, null, m_credit_limit,
                m_cust_email, null, null,
                v_date_of_birth, v_marital_status, m_gender, null );
        ELSE
            UPDATE OE.v_customer_detail_sensitive
            SET CUST_FIRST_NAME = m_cust_first_name,
                CUST_LAST_NAME = m_cust_last_name,
                --CUST_ADDRESS = m_cust_address,
                --PHONE_NUMBERS = m_phone_numbers,
                --NLS_LANGUAGE = m_nls_language,
                --NLS_TERRITORY = m_nls_territory,
                CREDIT_LIMIT = m_credit_limit,
                CUST_EMAIL = m_cust_email,
                --ACCOUNT_MGR_ID = m_account_mgr_id,
                --CUST_GEO_LOCATION = m_cust_geo_location,
                DATE_OF_BIRTH = v_date_of_birth,
                MARITAL_STATUS = v_marital_status,
                GENDER = m_gender --,
                --INCOME_LEVEL = v_income_level
            WHERE customer_id = m_customer_id;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'OE p_update_customers_sensitive' );
    END p_update_customers_sensitive;

END oe_sec_pkg;
/

GRANT EXECUTE ON oe.oe_sec_pkg TO oeview_role;
