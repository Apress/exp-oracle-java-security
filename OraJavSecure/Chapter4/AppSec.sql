-- Chapter4/AppSec.sql
-- Copyright 2011, David Coffin

-- Connect as our Application User
--CONNECT appsec;

-- Enable the non-default role needed in order to create procedures
SET ROLE appsec_role;
-- or SET ROLE ALL;

-- Assure the APPSEC_ROLE is enabled
SELECT * FROM sys.session_roles;

-- Create the Java structure for this sample Java Stored Procedure
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED myapp4 AS
package pkg4;
import java.sql.*;
import oracle.jdbc.driver.OracleDriver;
public class MyApp4 {
    public static String getOracleTime() {
        String timeString = null;
        Statement stmt = null;
        try {
            //Class.forName( "oracle.jdbc.driver.OracleDriver" );
            //new oracle.jdbc.OracleDriver();
            //Connection conn = new OracleDriver().defaultConnection();
            Connection conn = DriverManager.getConnection("jdbc:default:connection");
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery( "select sysdate from dual" );
            if( rs.next() ) {
                timeString = rs.getString(1);
            }
        } catch( Exception x ) {
            timeString = x.toString();
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return timeString;
    }
}
/

-- Create the Oracle function that encapsulates the Java Stored Procedure
CREATE OR REPLACE FUNCTION f_get_oracle_time
    RETURN VARCHAR2
    AS LANGUAGE JAVA
    NAME 'pkg4.MyApp4.getOracleTime() return java.lang.String';
/

-- Test the Java Stored Procedure - will return the current date and time
SELECT f_get_oracle_time FROM DUAL;

-- A much simpler approach with the same effect
SELECT SYSDATE FROM DUAL;

-- Remove our example Java Stored Procedure from the database
--DROP FUNCTION f_get_oracle_time;
--DROP JAVA SOURCE myapp4;
