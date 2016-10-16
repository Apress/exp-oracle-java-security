-- Chapter2/AppUsr.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appusr;

-- Execute these commands one at a time to see restricted access
-- APPUSR cannot see anything with his default role
SELECT * FROM hr.employees;

SELECT * FROM hr.v_employees_sensitive;

SELECT * FROM hr.v_employees_public;

-- If this succeeds, APPUSR will have the APPUSR_ROLE
EXEC appsec.p_check_hrview_access;

-- Still, APPUSR cannot see the structures with sensitive data
SELECT * FROM hr.employees;

SELECT * FROM hr.v_employees_sensitive;

-- This view is available to APPUSR with APPUSR_ROLE,
-- Note the sensitive columns are not shown
SELECT * FROM hr.v_employees_public;
