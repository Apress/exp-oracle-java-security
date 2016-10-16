// Copyright 2011, David Coffin
// Chapter8/AppOraSSO.java


import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import oracle.jdbc.OracleConnection;

import orajavsec.OracleJavaSecure;


public class AppOraSSO {
    public static void main( String[] args ) {
        try {
            String urlString = "jdbc:oracle:thin:appusr/password@localhost:1521:orcl";
            Class.forName( "oracle.jdbc.driver.OracleDriver" );
            OracleConnection conn =
                (OracleConnection)DriverManager.getConnection( urlString );

            OracleJavaSecure.setConnection( conn );
            
            //OracleConnection conn = OracleJavaSecure.setConnection( urlString );

            System.out.println( "\nIs proxy session: " + conn.isProxySession() );
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT USER " +
                ", SYS_CONTEXT('USERENV','PROXY_USER') " +
                ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                ", SYS_CONTEXT('USERENV','OS_USER') " +
                ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                ", SYS_CONTEXT('USERENV','TERMINAL') " +
                ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                " FROM DUAL" );
            if ( rs.next() ) {
                System.out.println( "user                 : " +
                        rs.getString( 1 ) );
                System.out.println( "userenv proxy_user   : " +
                        rs.getString( 2 ) );
                System.out.println( "userenv current_user : " +
                        rs.getString( 3 ) );
                System.out.println( "userenv session_user : " +
                        rs.getString( 4 ) );
                System.out.println( "userenv os_user      : " +
                        rs.getString( 5 ) );
                System.out.println( "userenv ip_address   : " +
                        rs.getString( 6 ) );
                System.out.println( "userenv terminal     : " +
                        rs.getString( 7 ) );
                System.out.println( "userenv client_id    : " +
                        rs.getString( 8 ) );
            }

            try {
                stmt.execute("CALL appsec.p_check_hrview_access()");
                stmt.execute("ALTER SESSION SET CURRENT_SCHEMA=hr");
                rs = stmt.executeQuery( "SELECT COUNT(*) FROM v_employees_public" );
                System.out.println( "Read HR view!!!!!!!!!!!!!!!!!!!!" );
            } catch( Exception y ) {
                System.out.println( "Cannot read HR view." );
            }

            OracleJavaSecure.closeConnection();

        } catch ( Exception x ) {
            x.printStackTrace();
        }
        System.exit( 0 );
    }
}