-- Chapter11/apver/AppverSys.sql
-- Copyright 2011, David Coffin
-- Modify IP Addresses in f_is_sso and p_appver_logon
-- Replace OSUSER with your OS UserID
-- Replace the placeholder passwords with a real, complex passwords

-- First set temporary environment to new instance of Oracle
-- set ORACLE_SID=apver

-- Copy initialization parameters file to default location
-- copy D:\app\oracle\admin\apver\pfile\init.ora D:\app\oracle\product\11.2.0\DBHOME_1\DATABASE\INITORCL.ORA

-- Create the Database from SQLPLUS
--D:\app\oracle\product\11.2.0\dbhome_1\BIN\sqlplus /NOLOG
-- On apver instance!
CONNECT / AS sysdba
SPOOL apver.log

-- Shut down existing database at this conection - should not be any
SHUTDOWN IMMEDIATE;

STARTUP NOMOUNT PFILE=D:\app\oracle\admin\apver\pfile\init.ora

@D:\app\oracle\admin\apver\pfile\ApVerDBCreate.sql;

-- VERY IMPORTANT! - do not neglect to set the passwords
-- change from default passwords, "change_on_install"
ALTER USER sys IDENTIFIED BY sys_password;
ALTER USER system IDENTIFIED BY system_password;
-- Also use sys_password in line below where we load catqm.sql

-- Next line requires init.ora copied to default location
CREATE SPFILE FROM PFILE;

-- Shutdown / Startup for SPFILE to come into play
SHUTDOWN IMMEDIATE
STARTUP

CONNECT sys AS sysdba;
-- Enter new password

-- Set the number of process higher in order to support more concurrent sessions
ALTER SYSTEM SET PROCESSES=500
    COMMENT='Allow more concurrent Application Verification sessions.'
    SCOPE=SPFILE;
-- Cannot update in memory (BOTH), update SPFILE then shutdown / startup to see

SHUTDOWN IMMEDIATE
STARTUP

CONNECT sys AS sysdba;
-- Enter new password

SELECT value FROM sys.v$parameter WHERE name = 'processes';

-- Build Data Dictionary Views
-- Specify exact files so not find older/other version files on system
-- catalog calls cdenv which creates all_users
@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\catalog.sql

-- Build PL/SQL procedural option
-- catproc calls catprc (needed for plsql) which creates all_source and all_source_ae
@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\catproc.sql
-- catproc also calls catpexec.sql calls execsec.sql calls
--   secconf.sql which configures default profile and auditing settings

-- Build sqlplus product user profile
@D:\app\oracle\product\11.2.0\dbhome_1\sqlplus\ADMIN\pupbld.sql

-- Need XDB for DBMS_NETWORK_ACL_ADMIN
-- SECUREFILE lobs cannot be used in non-ASSM tablespace "USERS", so say NO
-- Use real SYS password in following command
@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\catqm.sql sys_password users tempts1 NO

@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\utlmail.sql

@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\prvtmail.plb

-- Need not set java_pool_size and shared_pool_size to 150M each
--select name,value from v$parameter where name in ('shared_pool_size','java_pool_size');
-- IN 11g, both 0, handled automatically from MEMORY_TARGET / TARGET_SGA,
-- Auto-tuned as part of Automatic Memory Management
--ALTER SYSTEM SET shared_pool_size=150M;
--ALTER SYSTEM SET java_pool_size=150M;

-- Install DBMS_JAVA package
@D:\app\oracle\product\11.2.0\dbhome_1\javavm\install\initjvm.sql;
--@D:\app\oracle\product\11.2.0\dbhome_1\xdk\admin\initxml.sql;
--@D:\app\oracle\product\11.2.0\dbhome_1\xdk\admin\xmlja.sql;
@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\catjava.sql;
--@D:\app\oracle\product\11.2.0\dbhome_1\RDBMS\ADMIN\catexf.sql;

-- See what's installed - compare to what's installed in initial database
SELECT * FROM sys.all_registry_banners;

-- You would like to be able to connect to the new database as SYS from TOAD or
-- other GUI utility, but as yet there is no remote login password file (for SYSDBA)
-- Check this with an inoccuous command, grant sysdba to sys:
GRANT sysdba TO sys;
-- You will likely see this error:
-- ERROR at line 1:
---ORA-01994: GRANT failed: password file missing or disabled
EXIT

-- Create a remote SYSDBA login password file using the orapwd utility
-- Enter the correct sys password on the following command
--orapwd file=%ORACLE_HOME%\database\PWDapver.ora password=sys_password
