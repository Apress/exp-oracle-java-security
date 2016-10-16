-- Chapter7/HR.sql
-- Copyright 2011, David Coffin

-- We are dependent on Default installation of HR schema
-- HR has RESOURCE role which has these system privileges:
-- CREATE SEQUENCE, CREATE TRIGGER, CREATE CLUSTER, CREATE PROCEDURE,
-- CREATE TYPE, CREATE OPERATOR, CREATE TABLE, CREATE INDEXTYPE

-- Connect as our Human Resources (HR) Oracle sample schema user
--CONNECT hr;

-- Get all roles that have been granted
--SET ROLE ALL;
-- Should see default RESOURCE role and APPSEC_USER_ROLE
--SELECT * FROM sys.session_roles;


CREATE OR REPLACE PACKAGE hr.hr_sec_pkg IS

    TYPE RESULTSET_TYPE IS REF CURSOR;

    PROCEDURE p_select_employees_sensitive(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    PROCEDURE p_select_employees_secret(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    PROCEDURE p_select_employee_by_id_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_employee_id             employees.employee_id%TYPE );

    PROCEDURE p_select_employee_by_ln_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_last_name               employees.last_name%TYPE );

    PROCEDURE p_select_employee_by_raw_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_last_name               RAW );

    -- We installed this in the AppSec schema for Chapter 6 testing
    -- Reuse here for exchanging keys before updates
    PROCEDURE p_get_shared_passphrase(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2 );

    PROCEDURE p_update_employees_sensitive(
        m_employee_id        employees.employee_id%TYPE,
        m_first_name         employees.first_name%TYPE,
        m_last_name          employees.last_name%TYPE,
        m_email              employees.email%TYPE,
        m_phone_number       employees.phone_number%TYPE,
        m_hire_date          employees.hire_date%TYPE,
        m_job_id             employees.job_id%TYPE,
        crypt_salary         RAW,
        crypt_commission_pct RAW,
        m_manager_id         employees.manager_id%TYPE,
        m_department_id      employees.department_id%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 );

END hr_sec_pkg;
/

-- Grant Execute to this package only for roles who need it
CREATE OR REPLACE PACKAGE BODY hr.hr_sec_pkg IS

    PROCEDURE p_select_employees_sensitive(
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
            employee_id,
            first_name,
            last_name,
            email,
            phone_number,
            hire_date,
            job_id,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( salary ) ),
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( commission_pct ) ),
            manager_id,
            department_id
        FROM employees;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_select_employees_sensitive' );
    END p_select_employees_sensitive;

    PROCEDURE p_select_employees_secret(
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
            appsec.app_sec_pkg.f_get_crypt_data(
                TO_CHAR( employee_id ) ||', '||
                first_name ||', '||
                last_name ||', '||
                email ||', '||
                phone_number ||', '||
                TO_CHAR( hire_date ) ||', '||
                job_id ||', '||
                TO_CHAR( salary ) ||', '||
                TO_CHAR( commission_pct ) ||', '||
                TO_CHAR( manager_id ) ||', '||
                TO_CHAR( department_id )
            )
        FROM employees;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_select_employees_secret' );
    END p_select_employees_secret;

    PROCEDURE p_select_employee_by_id_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_employee_id             employees.employee_id%TYPE )
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
            employee_id,
            first_name,
            last_name,
            email,
            phone_number,
            hire_date,
            job_id,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( salary ) ),
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( commission_pct ) ),
            manager_id,
            department_id
        FROM employees
        WHERE employee_id = m_employee_id;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_select_employee_by_id_sens' );
    END p_select_employee_by_id_sens;

    PROCEDURE p_select_employee_by_ln_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_last_name               employees.last_name%TYPE )
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
            employee_id,
            first_name,
            last_name,
            email,
            phone_number,
            hire_date,
            job_id,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( salary ) ),
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( commission_pct ) ),
            manager_id,
            department_id
        FROM employees
        WHERE last_name = m_last_name;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_select_employee_by_ln_sens' );
    END p_select_employee_by_ln_sens;

    PROCEDURE p_select_employee_by_raw_sens(
        ext_modulus               VARCHAR2,
        ext_exponent              VARCHAR2,
        secret_pass_salt      OUT RAW,
        secret_pass_count     OUT RAW,
        secret_pass_algorithm OUT RAW,
        secret_pass           OUT RAW,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2,
        m_last_name               RAW )
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
            employee_id,
            first_name,
            last_name,
            email,
            phone_number,
            hire_date,
            job_id,
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( salary ) ),
            appsec.app_sec_pkg.f_get_crypt_data( TO_CHAR( commission_pct ) ),
            manager_id,
            department_id
        FROM employees
        WHERE last_name = UTL_RAW.CAST_TO_VARCHAR2( m_last_name );
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_select_employee_by_raw_sens' );
    END p_select_employee_by_raw_sens;

    -- We installed this in the AppSec schema for Chapter 6 testing
    -- Reuse here for exchanging keys before updates
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
        secret_pass_salt :=
            appsec.app_sec_pkg.f_get_crypt_secret_salt( ext_modulus, ext_exponent );
        secret_pass_count :=
            appsec.app_sec_pkg.f_get_crypt_secret_count( ext_modulus, ext_exponent );
        secret_pass :=
            appsec.app_sec_pkg.f_get_crypt_secret_pass( ext_modulus, ext_exponent );
        secret_pass_algorithm :=
            appsec.app_sec_pkg.f_get_crypt_secret_algorithm(ext_modulus, ext_exponent);
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_get_shared_passphrase' );
    END p_get_shared_passphrase;

    PROCEDURE p_update_employees_sensitive(
        m_employee_id        employees.employee_id%TYPE,
        m_first_name         employees.first_name%TYPE,
        m_last_name          employees.last_name%TYPE,
        m_email              employees.email%TYPE,
        m_phone_number       employees.phone_number%TYPE,
        m_hire_date          employees.hire_date%TYPE,
        m_job_id             employees.job_id%TYPE,
        crypt_salary         RAW,
        crypt_commission_pct RAW,
        m_manager_id         employees.manager_id%TYPE,
        m_department_id      employees.department_id%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 )
    IS
        test_emp_ct      NUMBER(6);
        v_salary         VARCHAR2(15); -- Plenty of space, eventually a NUMBER
        v_commission_pct VARCHAR2(15);
    BEGIN
        -- Note:  Use of this procedure assumes you have already done a select
        -- and that you are using the same Session Secret PassPhrase
        m_err_no := 0;
        v_salary := appsec.app_sec_pkg.f_get_decrypt_data( crypt_salary );
        v_commission_pct :=
            appsec.app_sec_pkg.f_get_decrypt_data( crypt_commission_pct );
        SELECT COUNT(*) INTO test_emp_ct FROM employees WHERE
            employee_id = m_employee_id;
        IF test_emp_ct = 0
        THEN
            INSERT INTO employees
                (employee_id, first_name, last_name, email, phone_number, hire_date,
                job_id, salary, commission_pct, manager_id, department_id)
            VALUES
                (employees_seq.NEXTVAL, m_first_name, m_last_name, m_email,
				m_phone_number, m_hire_date, m_job_id, v_salary, v_commission_pct,
				m_manager_id, m_department_id);
        ELSE
            -- Comment update of certain values during testing - date constraint
            UPDATE employees
            SET first_name = m_first_name, last_name = m_last_name, email = m_email,
                phone_number = m_phone_number,
                -- Job History Constraint -- hire_date = m_hire_date, job_id = m_job_id,
                salary = v_salary, commission_pct = v_commission_pct,
                manager_id = m_manager_id
                -- Job History Constraint -- , department_id = m_department_id
            WHERE employee_id = m_employee_id;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_update_employees_sensitive' );
    END p_update_employees_sensitive;

END hr_sec_pkg;
/

GRANT EXECUTE ON hr.hr_sec_pkg TO hrview_role;


SELECT last_number FROM user_sequences WHERE sequence_name='EMPLOYEES_SEQ';

DECLARE
    offset NUMBER;
    alter_command VARCHAR2(100);
    new_last_number NUMBER;
BEGIN
    SELECT (300 - last_number) INTO offset FROM user_sequences
        WHERE sequence_name='EMPLOYEES_SEQ';

    alter_command := 'ALTER SEQUENCE employees_seq INCREMENT BY ' ||
        TO_CHAR(offset) || ' MINVALUE 0';
    EXECUTE IMMEDIATE alter_command;

    SELECT employees_seq.NEXTVAL INTO new_last_number FROM DUAL;
    DBMS_OUTPUT.PUT_LINE( new_last_number );

    EXECUTE IMMEDIATE 'ALTER SEQUENCE employees_seq INCREMENT BY 1';
END;
/

SELECT last_number FROM user_sequences WHERE sequence_name='EMPLOYEES_SEQ';

INSERT INTO employees
    (employee_id, first_name, last_name, email, phone_number, hire_date,
    job_id, salary, commission_pct, manager_id, department_id)
VALUES
    (employees_seq.NEXTVAL, 'David', 'Coffin', 'DAVID.COFFIN',
    '800.555.1212', SYSDATE, 'SA_REP', 5000, 0.20, 147, 80);

COMMIT;


SELECT * FROM employees WHERE employee_id=300;

