-- Chapter9/AppSec.sql
-- Copyright 2011, David Coffin
-- Modify IP Addresses and work hours in p_check_hrview_access

-- Connect as our Application User
--CONNECT appsec;

-- Enable non-default role
SET ROLE appsec_role;


-- This a test of sending e-mail from Oracle
ALTER SESSION SET SMTP_OUT_SERVER = 'smtp.org.com';

CALL UTL_MAIL.SEND( 'myname@org.com', 'myname@org.com', '', '',
    'Response','2FactorCode' );

--DROP TABLE appsec.t_two_fact_cd_cache CASCADE CONSTRAINTS;
--TRUNCATE TABLE appsec.t_two_fact_cd_cache;

-- Create table to cache 2-factor codes
-- Initial 2-Factor Code length = 14, allow for 24
-- IPv4 addresses are 15 characters or less;
-- IPv6, 39 characters, 45 mapped to IPv4
CREATE TABLE appsec.t_two_fact_cd_cache
(
    employee_id   NUMBER(6) NOT NULL,
    two_factor_cd VARCHAR2(24 BYTE),
    ip_address    VARCHAR2(45 BYTE) DEFAULT SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ),
    distrib_cd    NUMBER(2),
    cache_ts      DATE DEFAULT SYSDATE
);

CREATE UNIQUE INDEX two_fact_cd_emp_id_pk ON appsec.t_two_fact_cd_cache
    (employee_id);

ALTER TABLE appsec.t_two_fact_cd_cache ADD (
    CONSTRAINT two_fact_cd_emp_id_pk
    PRIMARY KEY
    (employee_id)
    USING INDEX two_fact_cd_emp_id_pk
);

CREATE OR REPLACE VIEW v_two_fact_cd_cache AS SELECT * FROM appsec.t_two_fact_cd_cache;

INSERT INTO appsec.v_two_fact_cd_cache
( employee_id ,two_factor_cd )
VALUES
(300,'FAKE');

-- Tests
SELECT * FROM appsec.v_two_fact_cd_cache;
-- Test minutes calculation - run a couple times to see change
SELECT (SYSDATE-cache_ts)*24*60
FROM appsec.v_two_fact_cd_cache WHERE employee_id=300;

-- Do this after you run HR.sql
-- Assure tests return code when user OK, cache timeout OK and IP Address OK
SELECT c.two_factor_cd
    FROM appsec.v_two_fact_cd_cache c, hr.v_emp_mobile_nos m
    WHERE m.employee_id = c.employee_id
    --AND m.user_id = 'OSUSER'
    AND c.ip_address = SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' )
    AND ( SYSDATE - c.cache_ts )*24*60 < 10;
-- After timeout, restart cache aging for this entry
update appsec.v_two_fact_cd_cache
set two_factor_cd = 'Fake2', ip_address = '127.0.0.1', cache_ts=SYSDATE
where employee_id=300;

-- Not adding this to package -- no grants needed.
CREATE OR REPLACE FUNCTION appsec.f_is_cur_cached_cd( just_os_user VARCHAR2,
    two_factor_cd t_two_fact_cd_cache.two_factor_cd%TYPE )
RETURN VARCHAR2
AS
    cache_timeout_mins NUMBER := 10;
    return_char VARCHAR2(1) := 'N';
    cached_two_factor_cd v_two_fact_cd_cache.two_factor_cd%TYPE;
BEGIN
    SELECT c.two_factor_cd INTO cached_two_factor_cd
    FROM v_two_fact_cd_cache c, hr.v_emp_mobile_nos m
    WHERE m.employee_id = c.employee_id
    AND m.user_id = just_os_user
    AND c.ip_address = SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' )
    AND ( SYSDATE - c.cache_ts )*24*60 < cache_timeout_mins;
    IF cached_two_factor_cd = two_factor_cd
    THEN
        return_char := 'Y';
    END IF;
    RETURN return_char;
END f_is_cur_cached_cd;
/

-- Not adding this to package -- no grants needed.
CREATE OR REPLACE FUNCTION appsec.f_send_2_factor( just_os_user VARCHAR2 )
RETURN VARCHAR2
AS LANGUAGE JAVA
NAME 'orajavsec.OracleJavaSecure.distribute2Factor( java.lang.String ) return java.lang.String';
/

-- Test from Oracle Client
--ALTER SESSION SET SMTP_OUT_SERVER = 'smtp.org.com';
--CALL UTL_MAIL.SEND( 'response@org.com', 'myname@org.com', '', '', 'Response','There' );

-- Procedure used to verify access to Secure Application Role
-- This was initially defined in Chapter 2 - redefined in Chapter 8 and here
-- Now this procedure takes 3 arguments (previously NO arguments )!
-- Not adding this to package -- this is granted execute to PUBLIC.
CREATE OR REPLACE PROCEDURE appsec.p_check_hrview_access(
    two_factor_cd t_two_fact_cd_cache.two_factor_cd%TYPE,
    m_err_no  OUT NUMBER,
    m_err_txt OUT VARCHAR2 )
AUTHID CURRENT_USER
AS
    just_os_user    VARCHAR2(40);
    backslash_place NUMBER;
BEGIN
    m_err_no := 0;
    -- Upper case OS_USER and discard prepended domain name, if exists
    just_os_user := UPPER( SYS_CONTEXT( 'USERENV', 'OS_USER' ) );
    -- Back slash is not an escape character in this context
    -- Negative 1 indicates count left from the right end, get last backslash
    backslash_place := INSTR( just_os_user, '\', -1 );
    IF( backslash_place > 0 )
    THEN
        just_os_user := SUBSTR( just_os_user, backslash_place + 1 );
    END IF;
    -- For proxy connections
    IF( SYS_CONTEXT( 'USERENV', 'PROXY_USER' ) = 'APPUSR'
    AND ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    AND SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) =
        SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' )
    AND SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = just_os_user )
    THEN
        IF( two_factor_cd IS NULL OR two_factor_cd = '' )
        THEN
            m_err_txt := f_send_2_factor( just_os_user );
        ELSIF( f_is_cur_cached_cd( just_os_user, two_factor_cd ) = 'Y' )
        THEN
            EXECUTE IMMEDIATE 'SET ROLE hrview_role';
        ELSE
            -- Wrong or Old 2_factor code.  Could return message in M_ERR_TXT,
            -- or this will get their attention.
            RAISE NO_DATA_FOUND;
        END IF;
    END IF;
    -- For non-proxy connections
    IF( ( SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) LIKE '192.168.%' OR
        SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ) = '127.0.0.1' )
    AND TO_CHAR( SYSDATE, 'HH24' ) BETWEEN 7 AND 18
    AND SYS_CONTEXT( 'USERENV', 'SESSION_USER' ) = 'APPUSR'
    AND SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) = just_os_user )
    THEN
        IF( two_factor_cd IS NULL OR two_factor_cd = '' )
        THEN
            m_err_txt := f_send_2_factor( just_os_user );
        ELSIF( f_is_cur_cached_cd( just_os_user, two_factor_cd ) = 'Y' )
        THEN
            EXECUTE IMMEDIATE 'SET ROLE hrview_role';
        ELSE
            RAISE NO_DATA_FOUND;
        END IF;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        m_err_no := SQLCODE;
        m_err_txt := SQLERRM;
        app_sec_pkg.p_log_error( m_err_no, m_err_txt,
            'APPSEC p_check_hrview_access' );
END p_check_hrview_access;
/
