// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 9

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

import orajavsec.OracleJavaSecure;

public class TestOracleJavaSecure {
    public static void main( String[] args ) {
        try {
            // Passing 2-factor code in as argument on command line
            String args0 = "";
            if( args.length != 0 && args[0] != null ) args0 = args[0];
            args0 = OracleJavaSecure.checkFormat2Factor( args0 );

            // Call OracleJavaSecure to get a connection with 2-Factor traits
            OracleConnection conn = OracleJavaSecure.setConnection(
                "jdbc:oracle:thin:appusr/password@localhost:1521:orcl" );
            OracleCallableStatement stmt;
            int errNo;
            String errMsg;

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.p_check_hrview_access(?,?,?)" );
            stmt.registerOutParameter( 2, OracleTypes.NUMBER );
            stmt.registerOutParameter( 3, OracleTypes.VARCHAR );
            stmt.setString( 1, args0 );
            stmt.setInt(    2, 0 );
            stmt.setNull(   3, OracleTypes.VARCHAR );
            stmt.executeUpdate();
            errNo = stmt.getInt( 2 );
            errMsg = stmt.getString( 3 );
            if( errNo != 0 ) {
                System.out.println( "Oracle error 1) " + errNo + ", " + errMsg );
            } else if( args0.equals( "" ) ) {
                System.out.println( "DistribCd = " + errMsg );
                System.out.println( "Call again with 2-Factor code parameter" );
            } else {
                if( null != stmt ) stmt.close();
                System.out.println( "Oracle success 1)" );

                OracleResultSet rs = null;
                RAW sessionSecretDESPassPhrase = null;
                RAW sessionSecretDESAlgorithm = null;
                RAW sessionSecretDESSalt = null;
                RAW sessionSecretDESIterationCount = null;

                String locModulus = OracleJavaSecure.getLocRSAPubMod();
                String locExponent = OracleJavaSecure.getLocRSAPubExp();

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
                    if( null != rs ) rs.close();
                    if( null != stmt ) stmt.close();
                }
            }
            OracleJavaSecure.closeConnection();
        } catch( Exception x ) {
            System.out.println( "Local Exception:" );
            x.printStackTrace();
        }
        System.exit( 0 );
    }
}
/*
OraJavSecure\Chapter9>javac TestOracleJavaSecure.java

OraJavSecure\Chapter9>java TestOracleJavaSecure
DistribCd = 5
Call again with 2-Factor code parameter

OraJavSecure\Chapter9>java TestOracleJavaSecure
DistribCd = 0
Call again with 2-Factor code parameter

OraJavSecure\Chapter9>java TestOracleJavaSecure 7415-0535-8663
DistribCd = null
Oracle success 1)
Oracle success 2)
198, Donald, OConnell, DOCONNEL, 650.507.9833, 2007-06-21 00:00:00, SH_CLERK, 26
00 (AD6E5035FAB394A8), null, 124, 50

OraJavSecure\Chapter9>java TestOracleJavaSecure 7415-0535-8663
Domain: ORGDOMAIN, Name: OSUSER
DistribCd = ORA-01403: no data found
Oracle error 1) 100, ORA-01403: no data found

OraJavSecure\Chapter9>
*/