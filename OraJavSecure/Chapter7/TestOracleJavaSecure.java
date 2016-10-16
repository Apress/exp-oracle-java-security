// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 7

import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.ResultSet;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

import orajavsec.OracleJavaSecure;

public class TestOracleJavaSecure {
    public static void main( String[] args ) {
        Connection conn = null;
        try {
            private static String appusrConnString =
                "jdbc:oracle:thin:AppUsr/password@localhost:1521:Orcl";
            Class.forName( "oracle.jdbc.driver.OracleDriver" );
            conn = DriverManager.getConnection( appusrConnString );
            OracleCallableStatement stmt;
            OracleResultSet rs = null;
            ResultSet rset;
            RAW sessionSecretDESPassPhrase = null;
            RAW sessionSecretDESAlgorithm = null;
            RAW sessionSecretDESSalt = null;
            RAW sessionSecretDESIterationCount = null;
            int errNo;
            String errMsg;

            //OracleJavaSecure.setConnection( conn );
            String locModulus = OracleJavaSecure.getLocRSAPubMod();
            String locExponent = OracleJavaSecure.getLocRSAPubExp();
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.p_check_hrview_access()" );
            // Comment next line to see Exception when non-default role not set
            stmt.executeUpdate();

            // Once OracleCallableStatement statement established, can execute
            // standard queries, even if initially set up as prepared call
            rset = stmt.executeQuery(
                "SELECT * FROM hr.v_employees_public" );
            int cnt = 0;
            while( rset.next() ) cnt++;
            System.out.println( "Count data in V_EMPLOYEES_PUBLIC: " + cnt );

            rset = stmt.executeQuery(
                "SELECT COUNT(*) FROM hr.v_employees_public" );
            if( rset.next() ) cnt = rset.getInt(1);
            System.out.println( "Count data in V_EMPLOYEES_PUBLIC: " + cnt );

            if( null != stmt ) stmt.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_select_employees_sensitive(?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.RAW );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.CURSOR );
            stmt.registerOutParameter( 8, OracleTypes.NUMBER );
            stmt.registerOutParameter( 9, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.RAW );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            // This must go without saying - unsupported type for setNull
            //stmt.setNull( 7, OracleTypes.CURSOR );
            stmt.setInt(    8, 0 );
            stmt.setNull(   9, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 8 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 9 );
                System.out.println( "Oracle error 1) " + errNo +
                    ", " + errMsg );
            } else {
                System.out.println( "Oracle success 1)" );
                sessionSecretDESSalt = stmt.getRAW( 3 );
                sessionSecretDESIterationCount = stmt.getRAW( 4 );
                sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                //while( rs.next() ) {
                // Only show first row
                if( rs.next() ) {
                    System.out.print( rs.getString( 1 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 2 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 3 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 4 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 5 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 6 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 7 ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 8 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    if ( null != rs.getRAW( 8 ) )
                        System.out.print( " (" + rs.getRAW( 8 ).stringValue() +
                                ")" );
                    System.out.print( ", " );
                    // Most initial commissions in database are null
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 9 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    if ( null != rs.getRAW( 9 ) )
                        System.out.print( " (" + rs.getRAW( 9 ).stringValue() +
                                ")" );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 10 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 11 ) );
                    System.out.print( "\n" );
                }
            }
            if( null != rs ) rs.close();
            if( null != stmt ) stmt.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_select_employees_secret(?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.RAW );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.CURSOR );
            stmt.registerOutParameter( 8, OracleTypes.NUMBER );
            stmt.registerOutParameter( 9, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.RAW );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            stmt.setInt(    8, 0 );
            stmt.setNull(   9, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 8 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 9 );
                System.out.println( "Oracle error 2) " + errNo +
                    ", " + errMsg );
            } else {
                System.out.println( "Oracle success 2)" );
                // This is repetetive, but we will show there's no harm
                // As a standard practice, you may want to set these every time
                sessionSecretDESSalt = stmt.getRAW( 3 );
                sessionSecretDESIterationCount = stmt.getRAW( 4 );
                sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                // Only show first row
                if( rs.next() ) {
                    System.out.print( OracleJavaSecure.getDecryptData( rs.getRAW( 1 ),
                        sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    if( null != rs.getRAW( 1 ) )
                        System.out.print( " (" + rs.getRAW( 1 ).stringValue() +
                            ")" );
                    System.out.print( "\n" );
                }
            }
            // Automatically closes resultSet
            if( null != stmt ) stmt.close();

            // Executes Insert first time, Update thereafter
            // This version assumes your session has already exchanged keys
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_update_employees_sensitive(?,?,?,?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 12, OracleTypes.NUMBER );
            stmt.registerOutParameter( 13, OracleTypes.VARCHAR );
            stmt.setInt(    1, 300 );
            stmt.setString( 2, "David" );
            stmt.setString( 3, "Coffin" );
            stmt.setString( 4, "DAVID.COFFIN" );
            stmt.setString( 5, "800.555.1212" );
            stmt.setDate(   6, new Date( ( new java.util.Date() ).getTime() ) );
            stmt.setString( 7, "SA_REP" );
            // Note - may not have locModulus, locExponent,  at this time!
            stmt.setRAW(    8, OracleJavaSecure.getCryptData( "9000.25" ) );
            stmt.setRAW(    9, OracleJavaSecure.getCryptData( "0.15" ) );
            stmt.setInt(   10, 147 );
            stmt.setInt(   11, 80 );
            stmt.setInt(   12, 0 );
            stmt.setNull(  13, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 12 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 13 );
                System.out.println( "Oracle error 3) " + errNo + ", " + errMsg );
            }
            else System.out.println( "Oracle success 3)" );
            if( null != stmt ) stmt.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_select_employee_by_id_sens(?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.RAW );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.CURSOR );
            stmt.registerOutParameter( 8, OracleTypes.NUMBER );
            stmt.registerOutParameter( 9, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.RAW );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            stmt.setInt(    8, 0 );
            stmt.setNull(   9, OracleTypes.VARCHAR );
            stmt.setInt(   10, 300 ); // Employee ID 300
            stmt.executeUpdate();

            errNo = stmt.getInt( 8 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 9 );
                System.out.println( "Oracle error 4) " + errNo +
                    ", " + errMsg );
            } else {
                System.out.println( "Oracle success 4)" );
                // These should not have changed, so for testing, comment
                //sessionSecretDESSalt = stmt.getRAW( 3 );
                //sessionSecretDESIterationCount = stmt.getRAW( 4 );
                //sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                //sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                // Should be only one record for this Employee ID
                if( rs.next() ) {
                    System.out.print( rs.getString( 1 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 2 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 3 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 4 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 5 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 6 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 7 ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 8 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 9 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 10 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 11 ) );
                    System.out.print( "\n" );
                }
            }
            if( null != stmt ) stmt.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_select_employee_by_ln_sens(?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.RAW );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.CURSOR );
            stmt.registerOutParameter( 8, OracleTypes.NUMBER );
            stmt.registerOutParameter( 9, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.RAW );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            stmt.setInt(    8, 0 );
            stmt.setNull(   9, OracleTypes.VARCHAR );
            //stmt.setString(   10, "King" ); // Employees Janette and Steven King
            // Attempt SQL Injection - returns no records
            stmt.setString(   10, "King' or 'a'='a" );
            stmt.executeUpdate();

            errNo = stmt.getInt( 8 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 9 );
                System.out.println( "Oracle error 5) " + errNo +
                    ", " + errMsg );
            } else {
                System.out.println( "Oracle success 5) No data on failed SQL Injection" );
                // Not bothering to get the secret password key artifacts again
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                // Should be only two records for this last name
                while( rs.next() ) {
                    System.out.print( rs.getString( 1 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 2 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 3 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 4 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 5 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 6 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 7 ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 8 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 9 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 10 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 11 ) );
                    System.out.print( "\n" );
                }
            }
            if( null != stmt ) stmt.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_select_employee_by_raw_sens(?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.RAW );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.CURSOR );
            stmt.registerOutParameter( 8, OracleTypes.NUMBER );
            stmt.registerOutParameter( 9, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.RAW );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            stmt.setInt(    8, 0 );
            stmt.setNull(   9, OracleTypes.VARCHAR );
            //stmt.setRAW(   10, new RAW("King".getBytes()) ); // Employees Janette and Steven King
            // Attempt SQL Injection - returns no records
            stmt.setRAW(   10, new RAW("King' or 'a'='a".getBytes()) ); // Employees Janette and Steven King
            stmt.executeUpdate();

            errNo = stmt.getInt( 8 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 9 );
                System.out.println( "Oracle error 6) " + errNo +
                    ", " + errMsg );
            } else {
                System.out.println( "Oracle success 6) No data on failed SQL Injection" );
                // Not bothering to get the secret password key artifacts again
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                // Should be only two records for this last name
                while( rs.next() ) {
                    System.out.print( rs.getString( 1 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 2 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 3 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 4 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 5 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 6 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 7 ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 8 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 9 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 10 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 11 ) );
                    System.out.print( "\n" );
                }
            }
            if( null != stmt ) stmt.close();

            // Make new keys on the client
            OracleJavaSecure.resetKeys(); // Method for Chapter 7 testing only
            locModulus = OracleJavaSecure.getLocRSAPubMod();
            locExponent = OracleJavaSecure.getLocRSAPubExp();

            // Start new connection with new keys
            //if ( null != conn ) conn.close();
            //conn = DriverManager.getConnection( appusrConnString );
            //OracleJavaSecure.setConnection( conn );
            //stmt = ( OracleCallableStatement )conn.prepareCall(
            //    "CALL appsec.p_check_hrview_access()" );
            //stmt.executeUpdate();

            // This should fail - haven't exchanged keys yet
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_update_employees_sensitive(?,?,?,?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 12, OracleTypes.NUMBER );
            stmt.registerOutParameter( 13, OracleTypes.VARCHAR );
            stmt.setInt(    1, 300 );
            stmt.setString( 2, "David" );
            stmt.setString( 3, "Coffin" );
            stmt.setString( 4, "DAVID.COFFIN" );
            stmt.setString( 5, "800.555.1212" );
            stmt.setDate(   6, new Date( ( new java.util.Date() ).getTime() ) );
            stmt.setString( 7, "SA_REP" );
            stmt.setRAW(    8, OracleJavaSecure.getCryptData( "9500.50" ) );
            stmt.setRAW(    9, OracleJavaSecure.getCryptData( "0.25" ) );
            stmt.setInt(   10, 147 );
            stmt.setInt(   11, 80 );
            stmt.setInt(   12, 0 );
            stmt.setNull(  13, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 12 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 13 );
                //System.out.println( "Oracle error 7) " + errNo + ", " + errMsg );
                System.out.println( "Failed where expected - OK.  Need key exchange." );
            }
            else System.out.println( "Oracle success 7) -- whoops, should fail!" );

            // This is a basic key exchange, with no queries or updates
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_get_shared_passphrase(?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.RAW );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.NUMBER );
            stmt.registerOutParameter( 8, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.RAW );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            stmt.setInt(    7, 0 );
            stmt.setNull(   8, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 7 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 8 );
                System.out.println( "Oracle error 8) " + errNo +
                    ", " + errMsg );
                System.out.println( (stmt.getRAW( 3 )).toString() );
            } else {
                System.out.println( "Oracle success 8)" );
                sessionSecretDESSalt = stmt.getRAW( 3 );
                sessionSecretDESIterationCount = stmt.getRAW( 4 );
                sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                OracleJavaSecure.makeDESKey( sessionSecretDESPassPhrase,
                    sessionSecretDESAlgorithm, sessionSecretDESSalt,
                    sessionSecretDESIterationCount );
            }
            if( null != stmt ) stmt.close();

            // Executes Insert first time, Update thereafter
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL hr.hr_sec_pkg.p_update_employees_sensitive(?,?,?,?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 12, OracleTypes.NUMBER );
            stmt.registerOutParameter( 13, OracleTypes.VARCHAR );
            stmt.setInt(    1, 300 );
            stmt.setString( 2, "David" );
            stmt.setString( 3, "Coffin" );
            stmt.setString( 4, "DAVID.COFFIN" );
            stmt.setString( 5, "800.555.1212" );
            stmt.setDate(   6, new Date( ( new java.util.Date() ).getTime() ) );
            stmt.setString( 7, "SA_REP" );
            stmt.setRAW(    8, OracleJavaSecure.getCryptData( "9700.75" ) );
            stmt.setRAW(    9, OracleJavaSecure.getCryptData( "0.30" ) );
            stmt.setInt(   10, 147 );
            stmt.setInt(   11, 80 );
            stmt.setInt(   12, 0 );
            stmt.setNull(  13, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 12 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 13 );
                System.out.println( "Oracle error 9) " + errNo + ", " + errMsg );
            }
            else System.out.println( "Oracle success 9)" );
            if ( null != stmt ) stmt.close();

        } catch( Exception x ) {
            System.out.println( "Local Exception:" );
            x.printStackTrace();
        } finally {
            try {
                if( null != conn ) conn.close();
            } catch( Exception y ) {}
        }
        System.exit( 0 );
    }
}
