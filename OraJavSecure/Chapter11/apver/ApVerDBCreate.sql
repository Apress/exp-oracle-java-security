-- ApVerDBCreate.sql
-- From Chapter 11

CREATE DATABASE apver
--USER SYS IDENTIFIED BY password
--USER SYSTEM IDENTIFIED BY password
-- Do not list passwords here - change later with ALTER USER command
-- Very important to change from default passwords!
-- Ask yourself, "do you feel lucky?"
-- No, I mean, ask yourself if you are more likely to
-- forget to set the passwords in the next step or forget to go back
-- and redact these passwords from this file (above) some time later?
LOGFILE GROUP 1 ('D:\app\oracle\oradata\apver\REDO01a.log',
    'D:\app\oracle\oradata\apver\REDO01b.log') SIZE 16M,
GROUP 2 ('D:\app\oracle\oradata\apver\REDO02a.log',
    'D:\app\oracle\oradata\apver\REDO02b.log') SIZE 16M,
GROUP 3 ('D:\app\oracle\oradata\apver\REDO03a.log',
    'D:\app\oracle\oradata\apver\REDO03b.log') SIZE 16M
MAXINSTANCES 3
MAXLOGFILES 6
MAXLOGMEMBERS 2
MAXLOGHISTORY 1
MAXDATAFILES 10
CHARACTER SET AL32UTF8
NATIONAL CHARACTER SET AL16UTF16
EXTENT MANAGEMENT LOCAL
-- Mimimum sizes are required for space to build Data Dictionary Views and JVM
DATAFILE 'D:\app\oracle\oradata\apver\SYSTEM01.DBF' SIZE 512M REUSE
SYSAUX DATAFILE 'D:\app\oracle\oradata\apver\SYSAUX01.DBF' SIZE 512M REUSE
DEFAULT TABLESPACE users DATAFILE 'D:\app\oracle\oradata\apver\USERS01.DBF'
    SIZE 256M REUSE AUTOEXTEND ON MAXSIZE UNLIMITED
DEFAULT TEMPORARY TABLESPACE tempts1 TEMPFILE 'D:\app\oracle\oradata\apver\TEMP01.DBF'
    SIZE 16M REUSE
UNDO TABLESPACE undotbs1 DATAFILE 'D:\app\oracle\oradata\apver\UNDOTBS01.DBF'
    SIZE 64M REUSE AUTOEXTEND ON MAXSIZE UNLIMITED;
