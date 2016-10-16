-- Supplement/OEView/SH.sql
-- Copyright 2011, David Coffin

-- Requires Sample Schema installed

--CONNECT SH;

-- Add column to customers table to hold encrypted cust_year_of_birth
ALTER TABLE SH.customers
add
   cust_yob_encr RAW(2000);


-- Create trigger to expunge future archive records
CREATE OR REPLACE TRIGGER SH.t_customers_biur BEFORE INSERT OR UPDATE
    ON SH.customers FOR EACH ROW
BEGIN
    :new.cust_marital_status := '';
    :new.cust_income_level := '';
    :new.cust_yob_encr := appsec.f_mask(
        SYS.UTL_RAW.CAST_TO_RAW(TO_CHAR(:new.cust_year_of_birth)||'SufficientLength'),
        :new.cust_last_name,
        :new.cust_first_name );
    :new.cust_year_of_birth := 0;
END;
/

ALTER TRIGGER SH.t_customers_biur ENABLE;

-- Test update trigger
INSERT INTO SH.customers
( CUST_ID, CUST_FIRST_NAME, CUST_LAST_NAME, CUST_GENDER, CUST_YEAR_OF_BIRTH,
    CUST_MARITAL_STATUS, CUST_STREET_ADDRESS, CUST_POSTAL_CODE, CUST_CITY,
    CUST_CITY_ID, CUST_STATE_PROVINCE, CUST_STATE_PROVINCE_ID, COUNTRY_ID,
    CUST_MAIN_PHONE_NUMBER, CUST_INCOME_LEVEL, CUST_CREDIT_LIMIT, CUST_EMAIL,
    CUST_TOTAL, CUST_TOTAL_ID, CUST_SRC_ID, CUST_EFF_FROM, CUST_EFF_TO, CUST_VALID )
VALUES
( 200000, 'David', 'Coffin', 'M', 1999, 'Married', '1212 Second St.',
    '68524', 'Glasco', 51583, 'KS', 52630, 52790, '800-555-1212',
    'K: 250,000 - 299,999', 15000, 'coffin@org.com', 'Customer total',
    52772, NULL, SYSDATE, NULL, 'A' );

COMMIT;

SELECT * FROM SH.customers WHERE cust_id = 200000;
-- Observe the values of cust_marital_status, cust_income_level,
--  cust_year_of_birth and cust_yob_encr columns

DELETE FROM SH.customers WHERE cust_id = 200000;

COMMIT;

-- Apply trigger to all existing records
-- This takes a few minutes!  Only run this once!
DECLARE
  TYPE CustCurTyp  IS REF CURSOR;
  v_cust_cursor    CustCurTyp;
  cust_record      SH.customers%ROWTYPE;
  v_stmt_str      VARCHAR2(200);
BEGIN
  v_stmt_str := 'SELECT * FROM SH.customers';
  OPEN v_cust_cursor FOR v_stmt_str;
  v_stmt_str := 'UPDATE SH.customers set cust_year_of_birth = :y where cust_id = :i';
  LOOP
    FETCH v_cust_cursor INTO cust_record;
    EXECUTE IMMEDIATE v_stmt_str USING cust_record.cust_year_of_birth, cust_record.cust_id;
    EXIT WHEN v_cust_cursor%NOTFOUND;
  END LOOP;
  CLOSE v_cust_cursor;
END;
/

SELECT * FROM SH.customers;
-- Observe the values of cust_marital_status, cust_income_level,
--  cust_year_of_birth and cust_yob_encr columns

COMMIT;

CREATE OR REPLACE FORCE VIEW SH.v_customer_detail_sensitive
    AS SELECT
        CUST_ID, CUST_FIRST_NAME, CUST_LAST_NAME, CUST_GENDER,
        to_number(
            substr(
                SYS.UTL_RAW.CAST_TO_varchar2(
                    appsec.f_unmask(
                        cust_yob_encr,
                        cust_last_name,
                        cust_first_name
                    )
                ),
                1,
                4
            )
        ) CUST_YEAR_OF_BIRTH,
        CUST_MARITAL_STATUS, CUST_STREET_ADDRESS, CUST_POSTAL_CODE, CUST_CITY,
        CUST_CITY_ID, CUST_STATE_PROVINCE, CUST_STATE_PROVINCE_ID, COUNTRY_ID,
        CUST_MAIN_PHONE_NUMBER, CUST_INCOME_LEVEL, CUST_CREDIT_LIMIT, CUST_EMAIL,
        CUST_TOTAL, CUST_TOTAL_ID, CUST_SRC_ID, CUST_EFF_FROM, CUST_EFF_TO, CUST_VALID
    FROM SH.customers;

-- Do not grant this view to anyone - only use internally

SELECT * FROM SH.v_customer_detail_sensitive;
-- Observe the values of cust_year_of_birth

