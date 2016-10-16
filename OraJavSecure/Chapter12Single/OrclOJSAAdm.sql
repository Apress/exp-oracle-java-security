-- Chapter12Single/OJSAAdm.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT ojsaadm;

SELECT * FROM sys.proxy_users;

-- Private database link to apver as ojsaadm
--CREATE DATABASE LINK apver_link
--CONNECT TO ojsaadm
--IDENTIFIED BY password
--USING 'apver';

CREATE OR REPLACE VIEW ojsaadm.instance_proxy_users AS
--SELECT 'APVER' INSTANCE, proxy, client FROM sys.proxy_users@apver_link
--UNION
SELECT 'ORCL' INSTANCE, proxy, client FROM sys.proxy_users;

-- Test the link and view
SELECT * FROM ojsaadm.instance_proxy_users;

GRANT SELECT ON ojsaadm.instance_proxy_users TO ojs_adm_admin;

---------apver_usr_adm_pkg not required-------------------------------
