-- Supplement/OEView/SecAdm.sql
-- Copyright 2011, David Coffin

-- Requires Sample Schema installed

--CONNECT secadm;

EXEC sys.p_check_secadm_access;

-- From here, may have already been accomplished for TestAppC in Supplement
ALTER USER oe ACCOUNT UNLOCK;
ALTER USER oe IDENTIFIED BY password;

GRANT create_session_role TO oeview IDENTIFIED BY password;

CREATE ROLE oeview_role IDENTIFIED USING appsec.p_check_role_access;
-- To here

GRANT EXECUTE ON appsec.app_sec_pkg TO oe;

ALTER USER sh ACCOUNT UNLOCK;
ALTER USER sh IDENTIFIED BY password;

GRANT EXECUTE ON appsec.f_mask TO sh;
GRANT EXECUTE ON appsec.f_unmask TO sh;
