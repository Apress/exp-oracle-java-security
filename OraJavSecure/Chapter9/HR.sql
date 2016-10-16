-- Chapter9/HR.sql
-- Copyright 2011, David Coffin

-- Connect as our Human Resources (HR) Oracle sample schema user
--CONNECT hr;

-- Note, you will want to be dilligent in configuring tables
-- for expected size and growth, and storage space / location
CREATE TABLE hr.sms_carrier_host
(
    sms_carrier_cd  VARCHAR2(32 BYTE) NOT NULL,
    sms_carrier_url VARCHAR2(256 BYTE)
);

CREATE UNIQUE INDEX sms_carrier_host_cd_pk ON hr.sms_carrier_host
    (sms_carrier_cd);

ALTER TABLE hr.sms_carrier_host ADD (
    CONSTRAINT sms_carrier_host_cd_pk
    PRIMARY KEY
    (sms_carrier_cd)
    USING INDEX sms_carrier_host_cd_pk
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

CREATE UNIQUE INDEX emp_mob_nos_emp_id_pk ON hr.emp_mobile_nos
    (employee_id);

CREATE UNIQUE INDEX emp_mob_nos_usr_id_ui ON hr.emp_mobile_nos
    (user_id);

ALTER TABLE hr.emp_mobile_nos ADD (
    CONSTRAINT emp_mob_nos_emp_id_pk
    PRIMARY KEY
    (employee_id)
    USING INDEX emp_mob_nos_emp_id_pk,
    CONSTRAINT emp_mob_nos_usr_id_ui
    UNIQUE (user_id)
    USING INDEX emp_mob_nos_usr_id_ui
);

ALTER TABLE hr.emp_mobile_nos ADD (
  CONSTRAINT employee_id_fk
  FOREIGN KEY (employee_id)
  REFERENCES employees (employee_id),
  CONSTRAINT sms_carrier_cd_fk
  FOREIGN KEY (sms_carrier_cd)
  REFERENCES sms_carrier_host (sms_carrier_cd));

CREATE OR REPLACE VIEW v_emp_mobile_nos AS SELECT * FROM hr.emp_mobile_nos;

INSERT INTO hr.v_emp_mobile_nos
    ( employee_id, user_id, com_pager_no, sms_phone_no, sms_carrier_cd )
    VALUES ( 300, 'OSUSER', '12345', '8005551212', 'Verizon' );


-- Substitute your First name, Last name, E-Mail Address and User ID
INSERT INTO hr.employees
    (employee_id, first_name, last_name, email, phone_number, hire_date,
    job_id, salary, commission_pct, manager_id, department_id)
VALUES
    (hr.employees_seq.NEXTVAL, 'First', 'Last', 'EMAddress',
    '800.555.1212', SYSDATE, 'SA_REP', 5000, 0.20, 147, 80);

INSERT INTO hr.v_emp_mobile_nos
    ( employee_id, user_id, com_pager_no, sms_phone_no, sms_carrier_cd )
    VALUES ( (
        select employee_id from hr.employees where
        first_name = 'First' and last_name = 'Last'
    ), 'UserID', '12345', '8005551212', 'Verizon' );

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
