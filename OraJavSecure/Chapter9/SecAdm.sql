-- Chapter9/SecAdm.sql
-- Copyright 2011, David Coffin

-- Connect as our Security Administrator user
--CONNECT secadm;

-- Always execute procedure to acquire Security Administrator role
EXEC sys.p_check_secadm_access;


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
--ORA-06512: at "SYS.DBMS_JAVA", line 793
--29532. 00000 -  "Java call terminated by uncaught Java exception: %s"
--*Cause:    A Java exception or error was signaled and could not be
--           resolved by the Java code.
--*Action:   Modify Java code, if this behavior is not intended.
