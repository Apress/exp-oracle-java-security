-- Chapter11/apver/NewAppSec.sql
-- Copyright 2011, David Coffin
-- Replace the placeholder "password" with a real, complex password

-- Connect as our Application User
-- On apver instance!
--CONNECT appsec;

-- Enable non-default role
SET ROLE appsec_role;

CREATE DATABASE LINK orcl_link
CONNECT TO appsec
IDENTIFIED BY password
USING 'orcl';

-- Test the link
SELECT * FROM hr.v_emp_mobile_nos@orcl_link;

