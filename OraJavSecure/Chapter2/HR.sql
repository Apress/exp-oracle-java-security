-- Chapter2/HR.sql
-- Copyright 2010, David Coffin

-- Connect as our Human Resources (HR) Oracle sample schema user
--CONNECT hr;

-- If any grants have been given to PUBLIC for EMPLOYEES, revoke them here
--REVOKE SELECT, UPDATE, INSERT, DELETE ON hr.employees FROM PUBLIC;


-- View the contents of the EMPLOYEES table, including the snsitive data
SELECT * FROM hr.employees;

-- Create a view of the Employees data that excludes the sensitive columns
CREATE OR REPLACE VIEW hr.v_employees_public
AS SELECT
    employee_id,
    first_name,
    last_name,
    email,
    phone_number,
    hire_date,
    job_id,
    manager_id,
    department_id
FROM hr.employees;

-- Test our new view
SELECT * FROM hr.v_employees_public;

-- Allow our Secure HR Application role to view the public view
GRANT SELECT ON hr.v_employees_public TO hrview_role;

-- Create a view of all columns in EMPLOYEES - guard access to this view
CREATE OR REPLACE VIEW hr.v_employees_sensitive
    AS SELECT *
    FROM hr.employees;

-- Test our new view - observe the sensitive data
SELECT * FROM hr.v_employees_sensitive;

