// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 10

package testojs;

import java.io.Serializable;

import java.sql.ResultSet;
import java.sql.Statement;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

import orajavsec.OracleJavaSecure;
import orajavsec.RevLvlClassIntfc;

public class TestOracleJavaSecure {
    // Pass this class to Oracle for Application Authentication
    // Update rev level and store in Oracle
    // Remove old rev level class from Oracle to invalidate old code
    public static class AnyNameWeWant
        implements Serializable, RevLvlClassIntfc
    {
        // Structure and name (package and outer class) equal to application
        // Name difference - ClassNotFoundException
        // Structure difference - InvalidClassException
        private static final long serialVersionUID = 2011013100L;
        private String innerClassRevLvl = "20110131a";
        public String getRevLvl() {
            return innerClassRevLvl;
        }
    }

    public static void main( String[] args ) {
        OracleCallableStatement stmt = null;
        Statement mStmt = null;
        ResultSet rSet;
        try {
            // Submit 2-Factor auth code on command line, once received
            String twoFactorAuth = "";
            if( args.length != 0 && args[0] != null ) twoFactorAuth = args[0];
            String applicationID = "HRVIEW";
            Object appClass = new AnyNameWeWant();
            OracleJavaSecure.setAppContext( applicationID, appClass, twoFactorAuth );


            // Only do these lines once -- must be admin account
            // If we provided an old twoFactorAuth, will not have connHash -
            // null pointer exception here
            OracleJavaSecure.getAppConnections();
            OracleJavaSecure.putAppConnString( "Orcl", "appusr",
                "password", "localhost", String.valueOf( 1521 ) );
            OracleJavaSecure.putAppConnections();


            OracleConnection conn =
                OracleJavaSecure.getAAConnRole( "orcl", "appusr" );

            if( twoFactorAuth.equals( "" ) ) {
                System.out.println( "Call again with 2-Factor code parameter" );
                return;
            }

            int errNo;
            String errMsg;

            mStmt = conn.createStatement();

            rSet = mStmt.executeQuery( "SELECT SYS_CONTEXT( 'USERENV', 'OS_USER' )," +
            "SYS_CONTEXT( 'USERENV', 'PROXY_USER' ),SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ),"+
            "SYS_CONTEXT( 'USERENV', 'SESSION_USER' ),SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) " +
            "FROM DUAL" );
            if ( rSet.next() ) {
                System.out.println( rSet.getString( 1 ) );
                System.out.println( rSet.getString( 2 ) );
                System.out.println( rSet.getString( 3 ) );
                System.out.println( rSet.getString( 4 ) );
                System.out.println( rSet.getString( 5 ) );
            }
            rSet = mStmt.executeQuery( "SELECT * FROM sys.session_roles" );
            if ( rSet.next() ) {
                System.out.println( rSet.getString( 1 ) );
            }
            //rSet = mStmt.executeQuery( "SELECT COUNT(*) FROM hr.employees_public" );
            //if ( rSet.next() )
            //    System.out.println( rSet.getInt( 1 ) );

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
                OracleResultSet rs = ( OracleResultSet )stmt.getCursor( 7 );
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
                        rs.getRAW( 8 ), stmt.getRAW( 6 ),
                        stmt.getRAW( 5 ), stmt.getRAW( 3 ),
                        stmt.getRAW( 4 ) ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 9 ), stmt.getRAW( 6 ),
                        stmt.getRAW( 5 ), stmt.getRAW( 3 ),
                        stmt.getRAW( 4 ) ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 10 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 11 ) );
                    System.out.print( "\n" );
                }
                if( null != rs ) rs.close();
                if( null != stmt ) stmt.close();
            }
            
			OracleJavaSecure.closeConnection();
        } catch( Exception x ) {
            System.out.println( "Local Exception:" );
            x.printStackTrace();
        }
        System.exit( 0 );
    }
}
