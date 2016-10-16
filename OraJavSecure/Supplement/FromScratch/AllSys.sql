-- Supplement/FromScratch/AllSys.sql
-- Copyright 2011, David Coffin

-- Requires HR Sample Schema installed

-- Modify IP Addresses in f_is_sso and p_appver_logon
-- Replace OSUSER with your OS UserID (All Caps for insert - between quotes) - 6 occurrences
-- Replace OSADMIN with your OS UserID or other admin user ID - 9 occurrences
-- If you use the same OS user ID for both OSUSER and OSADMIN, only execute create user once for OS user
-- Replace the placeholder passwords (IDENTIFIED BY password) with real, complex passwords -- 7 occurrences
-- Substitute your name for David Coffin in employee 300

-- Connect as SYS using the SYSDBA "super" system privilege
-- Perhaps using TOAD
-- or sqlplus sys@orcl as sysdba
--CONNECT sys AS sysdba;

-- Start by dropping all existing structures that we built
-- Do this if you've built any of these strcutures on this instance
-- We drop most of our structures when we drop appsec user
--select * from all_users;
--drop user userone;
--drop user usertwo;
--drop user userthree;
--drop user userfour;
--drop user oeview;
--drop user apvrad;
--drop user rolead;
--drop user userad;
--drop user nonead;
--
-- Beware of this if you have used hr.employees for anything besides this effort
--delete from hr.emp_mobile_nos where employee_id > 299;
--delete from hr.employees where employee_id > 299;
--commit;
--
--BEGIN
--  DBMS_NETWORK_ACL_ADMIN.DROP_ACL (
--    acl          => 'smtp_acl_file.xml');
--  COMMIT;
--END;
--/
--
--drop PACKAGE hr.hr_pub_pkg;
--drop PACKAGE sys.appver_conns_role_pkg;
--drop ROLE appver_conns;
--drop PACKAGE sys.usr_role_adm_pkg;
--drop user avadmin;
--drop ROLE ojs_adm_admin;
--drop user ojsaadm cascade;
--drop ROLE appver_admin;
--drop USER appver;
--drop PROFILE appver_prof;
--drop ROLE hrview_role;
--drop TABLE hr.emp_mobile_nos cascade constraints;
--drop TABLE hr.sms_carrier_host cascade constraints;
--drop USER osadmin;
--drop USER osuser;
--drop PACKAGE hr.hr_sec_pkg;
--drop VIEW hr.v_employees_sensitive;
--drop VIEW hr.v_employees_public;
--drop ROLE appsec_role;
--drop user appusr;
--drop user appsec cascade;
--drop PROCEDURE sys.p_check_secadm_access;
--drop ROLE secadm_role;
--drop user secadm;
--drop ROLE create_session_role;
--commit;

-- Find and execute these files on your database system:
--@C:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\utlmail.sql
--@C:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\prvtmail.plb

-- Create a role of our own that only has create session
CREATE ROLE create_session_role NOT IDENTIFIED;
GRANT CREATE SESSION TO create_session_role;

-- Security Administrator
-- These scripts assume a default installation of Oracle 11g
-- if you have modified the default user privileges / profiles for new accounts
-- you may have to grant additional permissions
-- Warning:  Assign a complex password to this user
GRANT create_session_role TO secadm IDENTIFIED BY password;

-- Create a role for all Security Administrator privileges
CREATE ROLE secadm_role IDENTIFIED USING sys.p_check_secadm_access;

-- This is the Procedure that Identifies (authorizes) SECADM_ROLE
CREATE OR REPLACE PROCEDURE sys.p_check_secadm_access
AUTHID CURRENT_USER
AS
BEGIN
    -- This is a comment
    IF( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    THEN
        --DBMS_SESSION.SET_ROLE('secadm_role');
        EXECUTE IMMEDIATE 'SET ROLE secadm_role';
    END IF;
END;
/

-- All ow SECADM to execute the procedure
GRANT EXECUTE ON sys.p_check_secadm_access TO secadm;

-- Various system privileges are granted to SECADM_ROLE
GRANT
    CREATE USER
    ,ALTER USER
    ,CREATE ROLE
    ,GRANT ANY OBJECT PRIVILEGE
    ,GRANT ANY PRIVILEGE
    ,GRANT ANY ROLE
    ,CREATE ANY PROCEDURE
    ,CREATE ANY TRIGGER
    ,CREATE ANY CONTEXT
    ,CREATE PROFILE
    ,AUDIT SYSTEM
    ,AUDIT ANY
TO secadm_role;

-- SYS will configure auditing for the audit trail
AUDIT SELECT ON sys.dba_audit_trail BY ACCESS;
AUDIT SELECT ON sys.aud$ BY ACCESS;

-- Allow our Security Administrator role to see the more detailed views
-- in the Data Dictionary
GRANT select_catalog_role TO secadm_role;

-- Create a couple accounts for our use that can create sessions
-- Warning:  Assign a complex password to these users
-- Oracle Application (Java) Security
GRANT create_session_role TO appsec IDENTIFIED BY password;
-- Application User
GRANT create_session_role TO appusr IDENTIFIED BY password;

-- Role for privileges required by Application Security user
CREATE ROLE appsec_role NOT IDENTIFIED;
-- Give Application Security privilege to create Java Stored Procedures
GRANT CREATE PROCEDURE TO appsec_role;
-- Give Application Security privilege to create Tables and Views
GRANT CREATE TABLE TO appsec_role;
GRANT CREATE VIEW TO appsec_role;
-- Grant the role to APPSEC user
GRANT appsec_role TO appsec;

-- Make the APPSEC_ROLE a non-default role for the APPSEC user
ALTER USER appsec DEFAULT ROLE ALL EXCEPT appsec_role;

-- Auditing SECADM structures and access to HR.EMPLOYEES
AUDIT ALTER ANY PROCEDURE BY ACCESS;
-- This is one of the recommended audit statements

AUDIT SELECT ON hr.employees BY ACCESS;

-- If the HR user is not accessible, do this
-- Warning:  Assign a complex password to this user
ALTER USER hr ACCOUNT UNLOCK IDENTIFIED BY password;

-- Create a view of the Employees data that excludes the sensitive columns
CREATE OR REPLACE VIEW hr.v_employees_public
AS SELECT
    employee_id,
    first_name,
    last_name,
    email,
    phone_number,
    hire_date,
    job_id,
    manager_id,
    department_id
FROM hr.employees;

-- Create a view of all columns in EMPLOYEES - guard access to this view
CREATE OR REPLACE VIEW hr.v_employees_sensitive
    AS SELECT *
    FROM hr.employees;

-- We need a place and space to insert data associated with APPSEC
ALTER USER appsec DEFAULT TABLESPACE USERS QUOTA 10M ON USERS;

GRANT CREATE TRIGGER TO appsec_role;

-- You will want to be dilligent in configuring the tables
-- for expected size and growth, and establish old log purging schedule
CREATE TABLE appsec.t_appsec_errors (
    err_no     NUMBER,
    err_txt    VARCHAR2(2000),
    msg_txt    VARCHAR2(4000) DEFAULT NULL,
    update_ts  DATE DEFAULT SYSDATE
);

CREATE INDEX appsec.i_appsec_errors00 ON appsec.t_appsec_errors (
       update_ts
);

CREATE OR REPLACE VIEW appsec.v_appsec_errors AS SELECT * FROM appsec.t_appsec_errors;

CREATE TABLE appsec.t_appsec_errors_maint (
    update_ts DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX appsec.i_appsec_errors_maint00 ON appsec.t_appsec_errors_maint (
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
    AFTER INSERT ON appsec.t_appsec_errors FOR EACH ROW
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

-- We remedy this (described in book) by granting execute on the AppSec package directly to HR.
GRANT EXECUTE ON appsec.app_sec_pkg TO hr;

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

DECLARE
    offset NUMBER;
    alter_command VARCHAR2(100);
    new_last_number NUMBER;
BEGIN
    SELECT (300 - last_number) INTO offset FROM all_sequences
        WHERE sequence_name='EMPLOYEES_SEQ';

    alter_command := 'ALTER SEQUENCE hr.employees_seq INCREMENT BY ' ||
        TO_CHAR(offset) ;
    EXECUTE IMMEDIATE alter_command;

    SELECT hr.employees_seq.NEXTVAL INTO new_last_number FROM DUAL;
    DBMS_OUTPUT.PUT_LINE( new_last_number );

    EXECUTE IMMEDIATE 'ALTER SEQUENCE hr.employees_seq INCREMENT BY 1';
END;
/

INSERT INTO HR.employees
    (employee_id, first_name, last_name, email, phone_number, hire_date,
    job_id, salary, commission_pct, manager_id, department_id)
VALUES
    (HR.employees_seq.NEXTVAL, 'David', 'Coffin', 'DAVID.COFFIN',
    '800.555.1212', SYSDATE, 'SA_REP', 5000, 0.20, 147, 80);

COMMIT;


-- For proxy authentication, create a user that matches your operating system user ID
-- Substitute the user name you used to log into Windows for OSUSER
-- And grant him create session system privilege -
-- switching to proxy user requires establishing a new session!
-- And permit him to connect through your proxy user - APPUSR
CREATE USER osuser IDENTIFIED EXTERNALLY;
GRANT create_session_role TO osuser;
ALTER USER osuser GRANT CONNECT THROUGH appusr;

CREATE USER osadmin IDENTIFIED EXTERNALLY;
GRANT create_session_role TO osadmin;
ALTER USER osuser GRANT CONNECT THROUGH appusr;

-- Be aware that these auditing requests may generate a lot of data,
-- in which case you may want to specify them differently to get just essential data
AUDIT UPDATE TABLE, INSERT TABLE BY appusr ON BEHALF OF ANY;

GRANT EXECUTE ON sys.dbms_network_acl_admin TO secadm_role;

GRANT EXECUTE ON sys.utl_mail TO appsec_role;

CALL DBMS_JAVA.GRANT_POLICY_PERMISSION(
    'SECADM_ROLE', 'SYS',
    'java.net.SocketPermission',
    '*');

COMMIT;

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

-- Ignore this
--Error report:
--SQL Error: ORA-29532: Java call terminated by uncaught Java exception: java.lang.SecurityException: policy table update java.net.SocketPermission, www.org.com:80

COMMIT;

-- Note, you will want to be dilligent in configuring tables
-- for expected size and growth, and storage space / location
CREATE TABLE hr.sms_carrier_host
(
    sms_carrier_cd  VARCHAR2(32 BYTE) NOT NULL,
    sms_carrier_url VARCHAR2(256 BYTE)
);

CREATE UNIQUE INDEX hr.sms_carrier_host_cd_pk ON hr.sms_carrier_host
    (sms_carrier_cd);

ALTER TABLE hr.sms_carrier_host ADD (
    CONSTRAINT sms_carrier_host_cd_pk
    PRIMARY KEY
    (sms_carrier_cd)
    USING INDEX hr.sms_carrier_host_cd_pk
);

CREATE OR REPLACE VIEW hr.v_sms_carrier_host AS SELECT * FROM hr.sms_carrier_host;

-- Comprehensive lists of service provider SMTP hosts for SMS to cell phones
-- can be found on internet at http://en.wikipedia.org/wiki/List_of_SMS_gateways
-- Not to promote any carrier -- I dont use any of these
-- But to give some popular examples, let's insert these:
INSERT INTO hr.sms_carrier_host
    ( sms_carrier_cd, sms_carrier_url ) VALUES
    ( 'Alltel', 'message.alltel.com' );

INSERT INTO hr.sms_carrier_host
    ( sms_carrier_cd, sms_carrier_url ) VALUES
    ( 'AT_T', 'txt.att.net' );

INSERT INTO hr.sms_carrier_host
    ( sms_carrier_cd, sms_carrier_url ) VALUES
    ( 'Sprint', 'messaging.sprintpcs.com' );

INSERT INTO hr.sms_carrier_host
    ( sms_carrier_cd, sms_carrier_url ) VALUES
    ( 'Verizon', 'vtext.com' );

-- Adjust length of Pager_No and Phone_No as needed
CREATE TABLE hr.emp_mobile_nos
(
    employee_id     NUMBER (6) NOT NULL,
    user_id         VARCHAR2(20 BYTE) NOT NULL,
    com_pager_no    VARCHAR2(32 BYTE),
    sms_phone_no    VARCHAR2(32 BYTE),
    sms_carrier_cd  VARCHAR2(32 BYTE)
);

CREATE UNIQUE INDEX hr.emp_mob_nos_emp_id_pk ON hr.emp_mobile_nos
    (employee_id);

CREATE UNIQUE INDEX hr.emp_mob_nos_usr_id_ui ON hr.emp_mobile_nos
    (user_id);

ALTER TABLE hr.emp_mobile_nos ADD (
    CONSTRAINT emp_mob_nos_emp_id_pk
    PRIMARY KEY
    (employee_id)
    USING INDEX hr.emp_mob_nos_emp_id_pk,
    CONSTRAINT emp_mob_nos_usr_id_ui
    UNIQUE (user_id)
    USING INDEX hr.emp_mob_nos_usr_id_ui
);

ALTER TABLE hr.emp_mobile_nos ADD (
  CONSTRAINT employee_id_fk
  FOREIGN KEY (employee_id)
  REFERENCES hr.employees (employee_id),
  CONSTRAINT sms_carrier_cd_fk
  FOREIGN KEY (sms_carrier_cd)
  REFERENCES hr.sms_carrier_host (sms_carrier_cd));

CREATE OR REPLACE VIEW v_emp_mobile_nos AS SELECT * FROM hr.emp_mobile_nos;

INSERT INTO hr.v_emp_mobile_nos
    ( employee_id, user_id, com_pager_no, sms_phone_no, sms_carrier_cd )
    VALUES ( 300, 'OSUSER', '12345', '8035551212', 'Verizon' );

COMMIT;


-- We will be selecting HR data for 2-factor authentication
-- from procedures running as APPSEC
-- Now we need to get e-mail from public view of employees
-- Needs to select using the APPSEC schema user to keep from invalidating procedures
GRANT SELECT ON hr.v_employees_public TO appsec;
-- We need to get Carrier URL as APPSEC
GRANT SELECT ON hr.v_sms_carrier_host TO appsec;
-- APPSEC needs to read this table with only default roles
GRANT SELECT ON hr.v_emp_mobile_nos TO appsec;


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

CREATE UNIQUE INDEX appsec.two_fact_cd_emp_id_pk ON appsec.t_two_fact_cd_cache
    (employee_id,application_id);

ALTER TABLE appsec.t_two_fact_cd_cache ADD (
    CONSTRAINT two_fact_cd_emp_id_pk
    PRIMARY KEY
    (employee_id,application_id)
    USING INDEX appsec.two_fact_cd_emp_id_pk
);

CREATE OR REPLACE VIEW appsec.v_two_fact_cd_cache AS SELECT * FROM appsec.t_two_fact_cd_cache;

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

-- This body is going to be overwritten later
-- We need this now, but some things we need for the final version
-- Cannot be created until later
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

-- Procedure used to verify access to Secure Application Role
-- This was initially defined in Chapter 2 - redefined in Chapters 8, 9 and here
-- Now this procedure takes 3 arguments, as shown!
-- Not adding this to package -- this is granted execute to PUBLIC.
CREATE OR REPLACE PROCEDURE appsec.p_check_role_access(
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

GRANT EXECUTE ON appsec.appsec_public_pkg TO PUBLIC;


AUDIT EXECUTE ON appsec.p_check_role_access
    BY ACCESS
    WHENEVER NOT SUCCESSFUL;

-- Create Secure Application Role for accessing HR schema
CREATE ROLE hrview_role IDENTIFIED USING appsec.p_check_role_access;

-- After recreating role, redo grant
GRANT EXECUTE ON hr.hr_sec_pkg TO hrview_role;
-- Allow our Secure HR Application role to view the public view
GRANT SELECT ON hr.v_employees_public TO hrview_role;

-- Specify connect time and idle time in minutes - minimum is best
-- We need to maintain availability of this connection, so set
-- Unlimited Sessions, Password Lifetime and Failed Login Attempts
-- Limit burden this can put on server (DDOS) by limiting functionality
CREATE PROFILE appver_prof LIMIT
    CONNECT_TIME          1
    IDLE_TIME             1
    SESSIONS_PER_USER     UNLIMITED
    PASSWORD_LIFE_TIME    UNLIMITED
    FAILED_LOGIN_ATTEMPTS UNLIMITED;
-- Actually, sessions is limited by processes in database init.ora / pfile / spfile
-- default processes=150, set our specialized database (later) to 500

-- Go ahead and assign a password - this is one password that we use more like
-- an address.  It can be embedded into applications but is only useful for
-- application verification (identify an application to get access to resources)
CREATE USER appver
    IDENTIFIED BY password
    QUOTA 0 ON SYSTEM
    PROFILE appver_prof;

GRANT create_session_role TO appver;


-- Create APPSEC.P_APPVER_LOGON procedure before this
-- T_CHECK_APPVER_ACCESS is a logon trigger, only for the APPVER user
CREATE OR REPLACE TRIGGER secadm.t_screen_appver_access AFTER LOGON ON appver.SCHEMA
BEGIN
    appsec.p_appver_logon;
END;
/

ALTER USER osuser GRANT CONNECT THROUGH appver;
ALTER USER osadmin GRANT CONNECT THROUGH appver;


--AUDIT ALL STATEMENTS BY appver BY ACCESS; -- WHENEVER SUCCESSFUL;
AUDIT SELECT TABLE BY appver BY ACCESS;


AUDIT EXECUTE PROCEDURE
    BY appver
    BY ACCESS
    WHENEVER NOT SUCCESSFUL;

-- Must grant to user, not role since roles not exist without session
GRANT EXECUTE ON sys.dbms_crypto TO appsec;

-- Will be used to manage Application Verification Data
CREATE ROLE appver_admin NOT IDENTIFIED;

-- Possibly store keys table on separate database and select across a link
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
commit;


CREATE OR REPLACE PACKAGE appsec.appsec_admin_pkg IS

    PROCEDURE p_create_template_class(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_err_no     OUT NUMBER,
        m_err_txt    OUT VARCHAR2 );

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

    PROCEDURE p_create_template_class(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_err_no     OUT NUMBER,
        m_err_txt    OUT VARCHAR2 )
    IS
        v_count   INTEGER;
        v_package v_app_conn_registry.class_name%TYPE;
    BEGIN
        m_err_no := 0;
        SELECT COUNT(*) INTO v_count
        FROM sys.all_java_classes
        WHERE owner='APPSEC' AND name = m_class_name;
        IF v_count < 1 THEN
            v_count := INSTR( m_class_name, 'Login' );
            IF v_count > 0 THEN
                v_package := SUBSTR( m_class_name, 0, v_count - 2 );
                IF LENGTH( v_package ) > 0 THEN
                    EXECUTE IMMEDIATE
'CREATE AND RESOLVE JAVA SOURCE NAMED APPSEC.' || CHR(34) ||
v_package || '/Login' || CHR(34) || ' AS ' || CHR(13) || CHR(10) ||
'package ' || v_package || '; ' || CHR(13) || CHR(10) ||
'import java.io.Serializable; ' || CHR(13) || CHR(10) ||
'import orajavsec.RevLvlClassIntfc; ' || CHR(13) || CHR(10) ||
'public class Login { ' || CHR(13) || CHR(10) ||
'    public static class InnerRevLvlClass ' || CHR(13) || CHR(10) ||
'       implements Serializable, RevLvlClassIntfc{ ' || CHR(13) || CHR(10) ||
'        private static final long serialVersionUID = 2011010100L; ' || CHR(13) || CHR(10) ||
'        private String innerClassRevLvl = "20110101a"; ' || CHR(13) || CHR(10) ||
'        public String getRevLvl() { ' || CHR(13) || CHR(10) ||
'            return innerClassRevLvl; ' || CHR(13) || CHR(10) ||
'}   }   }';
                END IF;
            END IF;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'p_create_template_class' );
    END p_create_template_class;

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

GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_admin;

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

-- New user / role / package for administrative administration
GRANT create_session_role TO ojsaadm IDENTIFIED BY password;
CREATE ROLE ojs_adm_admin IDENTIFIED USING appsec.p_check_role_access;
ALTER USER osadmin GRANT CONNECT THROUGH ojsaadm;

GRANT SELECT ON hr.v_employees_public TO ojs_adm_admin;
GRANT SELECT ON hr.v_emp_mobile_nos TO ojs_adm_admin;

GRANT CREATE VIEW TO ojsaadm;

GRANT create_session_role TO avadmin IDENTIFIED BY password;
-- appver_admin is secure app role assigned to avadmin
ALTER USER osadmin GRANT CONNECT THROUGH avadmin;

GRANT SELECT ON appsec.v_application_registry TO ojs_adm_admin;

GRANT SELECT ON sys.proxy_users TO ojsaadm with grant option;


CREATE OR REPLACE PACKAGE sys.usr_role_adm_pkg IS

    PROCEDURE p_create_user_once( username sys.proxy_users.client%TYPE );

    PROCEDURE p_create_user_many( username sys.proxy_users.client%TYPE );

    PROCEDURE p_drop_user( username sys.proxy_users.client%TYPE );

    PROCEDURE p_set_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE );

    PROCEDURE p_drop_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE );

END usr_role_adm_pkg;
/

CREATE OR REPLACE PACKAGE BODY sys.usr_role_adm_pkg IS

    PROCEDURE p_create_user_once( username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'CREATE USER ' || username || ' IDENTIFIED EXTERNALLY';
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'user already exists for ' || username );
    END p_create_user_once;

    PROCEDURE p_create_user_many( username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'GRANT create_session_role TO ' || username;
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' GRANT CONNECT THROUGH appver';
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_create_user_many for ' || username );
    END p_create_user_many;

    PROCEDURE p_drop_user( username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' REVOKE CONNECT THROUGH appver';
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_drop_user for ' || username );
    END p_drop_user;

    PROCEDURE p_set_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' GRANT CONNECT THROUGH ' || proxyname;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_set_proxy_through for ' ||
                username || ' / ' || proxyname );
    END p_set_proxy_through;

    PROCEDURE p_drop_proxy_through(
        username sys.proxy_users.client%TYPE,
        proxyname sys.proxy_users.proxy%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'ALTER USER ' || username || ' REVOKE CONNECT THROUGH ' || proxyname;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.usr_role_adm_pkg.p_drop_proxy_through for ' ||
                username || ' / ' || proxyname );
    END p_drop_proxy_through;

END usr_role_adm_pkg;
/

-- Grant to role
GRANT EXECUTE ON sys.usr_role_adm_pkg TO ojs_adm_admin;

-- Would do as appsec user, but not granted ALTER ROLE
ALTER ROLE appver_admin IDENTIFIED USING appsec.p_check_role_access;

-- It is appsec user running the create Java in appsec_admin_pkg
-- Will need CREATE PROCEDURE
-- Non-default role not available
GRANT CREATE PROCEDURE TO appsec;
GRANT SELECT ON sys.all_java_classes TO appsec;


-- This role needed when only user proxy appver with create_session_role
-- Case when editing conn strings for alternate application
CREATE ROLE appver_conns NOT IDENTIFIED;
GRANT appver_conns TO osadmin;
GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_conns ;


CREATE OR REPLACE PACKAGE sys.appver_conns_role_pkg IS

    PROCEDURE p_grant_appver_conns_role (
        username sys.proxy_users.client%TYPE );

    PROCEDURE p_revoke_appver_conns_role (
        username sys.proxy_users.client%TYPE );

END appver_conns_role_pkg;
/

CREATE OR REPLACE PACKAGE BODY sys.appver_conns_role_pkg IS

    PROCEDURE p_grant_appver_conns_role (
        username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'GRANT appver_conns TO ' || username;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.p_grant_appver_conns_role for ' ||
                username );
    END p_grant_appver_conns_role;

    PROCEDURE p_revoke_appver_conns_role (
        username sys.proxy_users.client%TYPE )
    AS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        EXECUTE IMMEDIATE 'REVOKE appver_conns FROM ' || username;
        COMMIT;
    EXCEPTION
        WHEN OTHERS
        THEN
            appsec.app_sec_pkg.p_log_error( SQLCODE, SQLERRM,
                'sys.p_revoke_appver_conns_role for ' ||
                username );
    END p_revoke_appver_conns_role;

END appver_conns_role_pkg;
/

-- From New Application Registration
GRANT EXECUTE ON sys.appver_conns_role_pkg TO appver_admin ;

-- From Admin Users, Grant to user, not to role
GRANT EXECUTE ON sys.appver_conns_role_pkg TO ojsaadm;


-- Need with grant option so other schemas can see appsec view based on this
GRANT SELECT ON SYS.DBA_TAB_PRIVS TO appsec WITH GRANT OPTION;

-- SKIPPING Virtual Private Database

GRANT SELECT ON hr.v_sms_carrier_host TO hrview_role;

CREATE OR REPLACE PACKAGE hr.hr_pub_pkg IS

    TYPE RESULTSET_TYPE IS REF CURSOR;

    PROCEDURE p_select_emp_mobile_nos_by_id(
        m_employee_id             emp_mobile_nos.employee_id%TYPE,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2);

    PROCEDURE p_update_emp_mobile_nos(
        m_employee_id        emp_mobile_nos.employee_id%TYPE,
        m_user_id            emp_mobile_nos.user_id%TYPE,
        m_com_pager_no       emp_mobile_nos.com_pager_no%TYPE,
        m_sms_phone_no       emp_mobile_nos.sms_phone_no%TYPE,
        m_sms_carrier_cd     emp_mobile_nos.sms_carrier_cd%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 );

END hr_pub_pkg;
/

-- Grant Execute to this package only for roles who need it
CREATE OR REPLACE PACKAGE BODY hr.hr_pub_pkg IS

    PROCEDURE p_select_emp_mobile_nos_by_id(
        m_employee_id             emp_mobile_nos.employee_id%TYPE,
        resultset_out         OUT RESULTSET_TYPE,
        m_err_no              OUT NUMBER,
        m_err_txt             OUT VARCHAR2)
    IS BEGIN
        m_err_no := 0;
        OPEN resultset_out FOR SELECT
            user_id,
            com_pager_no,
            sms_phone_no,
            sms_carrier_cd
        FROM v_emp_mobile_nos
        WHERE employee_id = m_employee_id;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_select_emp_mobile_nos_by_id' );
    END p_select_emp_mobile_nos_by_id;

    PROCEDURE p_update_emp_mobile_nos(
        m_employee_id        emp_mobile_nos.employee_id%TYPE,
        m_user_id            emp_mobile_nos.user_id%TYPE,
        m_com_pager_no       emp_mobile_nos.com_pager_no%TYPE,
        m_sms_phone_no       emp_mobile_nos.sms_phone_no%TYPE,
        m_sms_carrier_cd     emp_mobile_nos.sms_carrier_cd%TYPE,
        m_err_no         OUT NUMBER,
        m_err_txt        OUT VARCHAR2 )
    IS
        test_emp_ct      NUMBER(6);
    BEGIN
        -- Note:  Use of this procedure assumes you have already done a select
        -- and that you are using the same Session Secret PassPhrase
        m_err_no := 0;
        SELECT COUNT(*) INTO test_emp_ct FROM v_emp_mobile_nos WHERE
            employee_id = m_employee_id;
        IF test_emp_ct = 0
        THEN
            INSERT INTO v_emp_mobile_nos
                (employee_id, user_id, com_pager_no, sms_phone_no, sms_carrier_cd)
            VALUES
                (m_employee_id, m_user_id, m_com_pager_no, m_sms_phone_no,
                m_sms_carrier_cd);
        ELSE
            UPDATE v_emp_mobile_nos
            SET user_id = m_user_id, com_pager_no = m_com_pager_no,
                sms_phone_no = m_sms_phone_no,
                sms_carrier_cd = m_sms_carrier_cd
            WHERE employee_id = m_employee_id;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            m_err_no := SQLCODE;
            m_err_txt := SQLERRM;
            appsec.app_sec_pkg.p_log_error( m_err_no, m_err_txt,
                'HR p_update_emp_mobile_nos' );
    END p_update_emp_mobile_nos;

END hr_pub_pkg;
/

GRANT EXECUTE ON hr.hr_pub_pkg TO hrview_role;

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','APPUSR','HRVIEW_ROLE');

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','OJSAADM','OJS_ADM_ADMIN');

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','AVADMIN','APPVER_ADMIN');

COMMIT;


-- Administrator users who can access applications
CREATE TABLE appsec.t_application_admins
(
    -- match appsec.t_app_conn_registry.class_name
    class_name VARCHAR2(2000) NOT NULL,
    -- match hr.emp_mobile_nos.user_id
    user_id    VARCHAR2(20) NOT NULL
);
/

CREATE UNIQUE INDEX appsec.application_admins_pk ON appsec.t_application_admins
    ( class_name, user_id );

ALTER TABLE appsec.t_application_admins ADD (
    CONSTRAINT application_admins_pk
    PRIMARY KEY
    ( class_name, user_id )
    USING INDEX appsec.application_admins_pk
);
/

CREATE OR REPLACE VIEW appsec.v_application_admins
    AS SELECT * FROM appsec.t_application_admins;

INSERT INTO appsec.v_application_admins
    ( class_name, user_id )
    ( SELECT DISTINCT class_name, 'OSADMIN' FROM appsec.t_app_conn_registry );

INSERT INTO appsec.v_application_admins
    ( class_name, user_id ) VALUES
    ( 'orajavsec.Login$InnerRevLvlClass', 'OSADMIN' );

COMMIT;


CREATE TABLE appsec.t_app_class_id
(
    class_name    VARCHAR2(2000 BYTE) NOT NULL ENABLE,
    application_id VARCHAR2(24 BYTE) NOT NULL ENABLE
);
/

CREATE UNIQUE INDEX appsec.app_class_id_pk ON appsec.t_app_class_id
    ( class_name, application_id );

ALTER TABLE appsec.t_app_class_id ADD (
    CONSTRAINT app_class_id_pk
    PRIMARY KEY
    ( class_name, application_id )
    USING INDEX appsec.app_class_id_pk
);
/

CREATE OR REPLACE VIEW appsec.v_app_class_id AS SELECT * FROM appsec.t_app_class_id;

INSERT INTO appsec.v_app_class_id
(CLASS_NAME, APPLICATION_ID) VALUES
('testojs.TestOracleJavaSecure$AnyNameWeWant','HRVIEW');

INSERT INTO appsec.v_app_class_id
(CLASS_NAME, APPLICATION_ID) VALUES
('orajavsec.Login$InnerRevLvlClass','OJSADMIN');

COMMIT;

GRANT SELECT ON appsec.v_app_class_id TO appver_admin ;
GRANT SELECT ON appsec.v_application_registry TO appver_admin;
GRANT SELECT ON appsec.v_app_conn_registry TO appver_admin;

GRANT INSERT ON appsec.v_app_class_id TO appver_admin ;
GRANT INSERT ON appsec.v_application_registry TO appver_admin ;
GRANT INSERT ON appsec.v_application_admins TO appver_admin;

GRANT UPDATE, SELECT, DELETE ON appsec.v_application_admins TO osadmin;

CREATE OR REPLACE VIEW ojsaadm.instance_proxy_users AS
SELECT 'ORCL' INSTANCE, proxy, client FROM sys.proxy_users;

GRANT SELECT ON ojsaadm.instance_proxy_users TO ojs_adm_admin;
GRANT SELECT ON ojsaadm.instance_proxy_users TO appsec;

-- Instead, update code of p_get_class_conns and p_set_class_conns
-- This is a combination of standard Chapter12 and non-apver Chapter11
-- Remove reference to and select from across a link
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
        --appsec.app_sec_pkg.p_log_error( 125, 'dave',
        --'p_get_class_conns for: ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );
        SELECT class_instance, connections
        INTO m_class_instance, m_connections
        FROM appsec.v_app_conn_registry
        WHERE class_name = m_class_name
        AND class_version = m_class_version
        AND class_name IN ( SELECT class_name FROM appsec.v_app_class_id
        WHERE application_id IN (
        SELECT application_id FROM appsec.v_application_registry
        WHERE app_user IN (
        SELECT proxy FROM ojsaadm.instance_proxy_users
        WHERE client = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )))
        UNION SELECT class_name FROM appsec.v_application_admins
        WHERE user_id = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
        OR SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = (
        SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
        WHERE TABLE_NAME='V_APPLICATION_ADMINS'
        AND OWNER='APPSEC'
        AND PRIVILEGE='UPDATE'
        AND GRANTEE=SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )));
    END p_get_class_conns;

    PROCEDURE p_set_class_conns(
        m_class_name     v_app_conn_registry.class_name%TYPE,
        m_class_version  v_app_conn_registry.class_version%TYPE,
        m_class_instance v_app_conn_registry.class_instance%TYPE,
        m_connections    v_app_conn_registry.connections%TYPE )
    IS
        v_count INTEGER;
        v_count_able INTEGER;
    BEGIN
        --appsec.app_sec_pkg.p_log_error( 126, 'dave',
        --'p_set_class_conns for: ' || SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) );
        SELECT COUNT(*) INTO v_count
            FROM appsec.v_app_conn_registry
            WHERE class_name = m_class_name
            AND class_version = m_class_version;
        SELECT COUNT(*) INTO v_count_able
            FROM appsec.v_app_conn_registry
            WHERE class_name = m_class_name
            AND class_version = m_class_version
            AND class_name IN (
            SELECT class_name FROM appsec.v_application_admins
            WHERE user_id = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
            OR SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = (
            SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
            WHERE TABLE_NAME='V_APPLICATION_ADMINS'
            AND OWNER='APPSEC'
            AND PRIVILEGE='UPDATE'
            AND GRANTEE=SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )));
        IF v_count = 0 THEN
            INSERT INTO v_app_conn_registry ( class_name, class_version,
                class_instance, connections ) VALUES
                ( m_class_name, m_class_version, m_class_instance, m_connections );
        ELSE
            IF v_count_able > 0 THEN
                UPDATE v_app_conn_registry
                    SET class_instance = m_class_instance,
                    connections = m_connections, update_dt = SYSDATE
                WHERE class_name = m_class_name
                AND class_version = m_class_version;
            END IF;
        END IF;
    END p_set_class_conns;

    FUNCTION f_get_crypt_conns(
        class_instance  v_app_conn_registry.class_instance%TYPE )
    RETURN RAW
    AS LANGUAGE JAVA
    NAME 'orajavsec.OracleJavaSecure.getCryptConns( oracle.sql.RAW ) return oracle.sql.RAW';

END appsec_only_pkg;
/

CREATE OR REPLACE VIEW appsec.v_app_conn_registry_filtered
AS
    SELECT * FROM appsec.t_app_conn_registry
    WHERE class_name IN (
        SELECT class_name FROM appsec.v_application_admins
        WHERE user_id = SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
    OR SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = (
        SELECT GRANTEE FROM SYS.DBA_TAB_PRIVS
        WHERE TABLE_NAME='V_APPLICATION_ADMINS'
        AND OWNER='APPSEC'
        AND PRIVILEGE='UPDATE'
        AND GRANTEE=SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )));

GRANT SELECT ON appsec.v_app_conn_registry_filtered TO appver_admin;

-- Assure this did not get revoked / dropped
GRANT EXECUTE ON appsec.appsec_admin_pkg TO appver_admin ;


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

-- Also create Java sources on Oracle database
-- OJSC.java, RevLvlClassIntfc.java, OracleJavaSecure.java
