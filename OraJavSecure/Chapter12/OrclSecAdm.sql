-- Chapter12/OrclSecAdm.sql
-- Copyright 2011, David Coffin

-- Replace OSADMIN with your OS UserID
-- Replace the placeholder "password" with a real, complex password

-- Connect as our Security Administrator user
--CONNECT secadm;

-- Always execute procedure to acquire Security Administrator role
EXEC sys.p_check_secadm_access;

-- New user / role / package for administrative administration
GRANT create_session_role TO ojsaadm IDENTIFIED BY password;
CREATE ROLE ojs_adm_admin IDENTIFIED USING appsec.p_check_role_access;
ALTER USER osadmin GRANT CONNECT THROUGH ojsaadm;

GRANT SELECT ON hr.v_employees_public TO ojs_adm_admin;
GRANT SELECT ON hr.v_emp_mobile_nos TO ojs_adm_admin;

GRANT CREATE DATABASE LINK TO ojsaadm;
GRANT CREATE VIEW TO ojsaadm;
GRANT CREATE PROCEDURE TO ojsaadm;

GRANT create_session_role TO avadmin IDENTIFIED BY password;
-- appver_admin is secure app role assigned to avadmin
ALTER USER osadmin GRANT CONNECT THROUGH avadmin;

GRANT SELECT ON appsec.v_application_registry TO ojs_adm_admin;
