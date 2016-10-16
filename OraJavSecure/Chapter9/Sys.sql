-- Chapter8/Sys.sql
-- Copyright 2011, David Coffin

-- Connect as SYS using the SYSDBA "super" system privilege
--CONNECT sys AS sysdba;

-- Find these files on your database system:
-- \app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\utlmail.sql and prvtmail.plb
-- execute the contents as SYS
-- From SQLPLUS, run:
--@C:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\utlmail.sql
--@C:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\prvtmail.plb

-- OR from TOAD / SQL Devloper / JDeveloper,
-- open the files and copy the text to the SQL editor
-- then execute as a script

GRANT EXECUTE ON sys.dbms_network_acl_admin TO secadm_role;

GRANT EXECUTE ON sys.utl_mail TO appsec_role;

CALL DBMS_JAVA.GRANT_POLICY_PERMISSION(
    'SECADM_ROLE', 'SYS',
    'java.net.SocketPermission',
    '*');

COMMIT;

-- After SECADM script
SELECT * FROM sys.dba_network_acls;
SELECT * FROM sys.dba_network_acl_privileges;

SELECT u.user#, u.name, p.name, p.type_name, p.action
FROM sys.user$ u, sys.java$policy$ p
WHERE p.name LIKE '%java.net.SocketPermission%'
AND p.grantee# = u.user#;

--SELECT * FROM sys.aud$
--ORDER BY ntimestamp# DESC;

--SELECT * FROM sys.fga_log$;

