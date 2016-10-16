-- Supplement/testojs/SecAdm.sql
-- Copyright 2011, David Coffin

-- Requires Sample Schema installed

--CONNECT secadm;

EXEC sys.p_check_secadm_access;

ALTER USER oe ACCOUNT UNLOCK;
ALTER USER oe IDENTIFIED BY password;

GRANT create_session_role TO oeview IDENTIFIED BY password;

CREATE ROLE oeview_role IDENTIFIED USING appsec.p_check_role_access;

ALTER USER osadmin GRANT CONNECT THROUGH oeview;
