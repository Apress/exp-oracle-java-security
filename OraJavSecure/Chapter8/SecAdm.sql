-- Chapter8/SecAdm.sql
-- Copyright 2011, David Coffin
-- Replace OSUSER with your OS UserID

-- Connect as our Security Administrator user
--CONNECT secadm;

-- Always execute procedure to acquire Security Administrator role
EXEC sys.p_check_secadm_access;

-- This query will show audit trail entries with Client Identification set
-- (Also try it without the where clause)
SELECT * FROM sys.dba_audit_trail
WHERE client_id IS NOT NULL
ORDER BY TIMESTAMP DESC;

-- For proxy authentication, create a user that matches your operating system user ID
-- Substitute the user name you used to log into Windows for OSUSER
-- And grant him create session system privilege -
-- switching to proxy user requires establishing a new session!
-- And permit him to connect through your proxy user - APPUSR
CREATE USER osuser IDENTIFIED EXTERNALLY;
GRANT create_session_role TO osuser;
ALTER USER osuser GRANT CONNECT THROUGH appusr;

-- Be aware that these auditing requests may generate a lot of data,
-- in which case you may want to specify them differently to get just essential data
AUDIT UPDATE TABLE, INSERT TABLE BY appusr ON BEHALF OF ANY;
-- This would be nice, but every java call gets audited with this command
--AUDIT EXECUTE PROCEDURE BY appusr ON BEHALF OF ANY;
NOAUDIT EXECUTE PROCEDURE BY appusr ON BEHALF OF ANY;

-- This query will show audit trail entries for proxy connections
SELECT p.username proxy, u.os_username, u.username, u.userhost, u.terminal,
u.timestamp, u.owner, u.obj_name, u.action_name, u.client_id, u.proxy_sessionid
FROM sys.dba_audit_trail u, sys.dba_audit_trail p
WHERE u.proxy_sessionid = p.sessionid
ORDER BY u.timestamp DESC;
