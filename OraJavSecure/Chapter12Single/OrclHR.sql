-- Chapter12Single/OrclHR.sql
-- Copyright 2011, David Coffin

-- Connect as our Human Resources (HR) Oracle sample schema user
--CONNECT hr;

GRANT SELECT ON hr.v_employees_public TO hrview_role;
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


