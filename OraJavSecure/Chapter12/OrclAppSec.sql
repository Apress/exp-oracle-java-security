-- Chapter12/OrclAppSec.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appsec;

-- Enable non-default role
SET ROLE appsec_role;

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','APPUSR','HRVIEW_ROLE');

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','OJSAADM','OJS_ADM_ADMIN');

INSERT INTO appsec.v_application_registry
(application_id, app_user, app_role) VALUES
('OJSADMIN','AVADMIN','APPVER_ADMIN');

