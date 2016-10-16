-- Supplement/OEView/OE.sql
-- Copyright 2011, David Coffin

-- Requires Sample Schema installed

--CONNECT OE;

CREATE OR REPLACE FORCE VIEW OE.v_customer_detail
AS SELECT * FROM OE.customers;

GRANT SELECT ON OE.v_customer_detail TO oeview_role;

SELECT * FROM oe.v_customer_detail ;
