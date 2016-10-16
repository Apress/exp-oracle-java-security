// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath
// Also have orajavsec/OracleJavaSecure.class on your classpath

// From Chapter 7

/*
 * Replace APPSCHEMA with your app schema name
 * Replace APPTABLE with the name of a sensitive table whose data you protect
 * Replace COLUMNx with your table column names
 * Replace SENS_COLUMNx with names of your sensitive columns
 * Replace APPSCHEMA_SEC_PKG with the name of your security package
 */

import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.ResultSet;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

import orajavsec.OracleJavaSecure;

public class AppAccessSecure {
    public static void main( String[] args ) {
        Connection conn = null;
        try {
            // This section of code sets up Application Encrypted Data Exchange
            // Edit the Oracle connection String to be appropriate for your use
            Class.forName( "oracle.jdbc.driver.OracleDriver" );
            conn = DriverManager.getConnection(
                "jdbc:oracle:thin:appusr/password@localhost:1521:Orcl" );
            OracleCallableStatement stmt;
            OracleResultSet rs = null;
            ResultSet rset;
            RAW sessionSecretDESPassPhrase = null;
            RAW sessionSecretDESAlgorithm = null;
            RAW sessionSecretDESSalt = null;
            RAW sessionSecretDESIterationCount = null;
            int errNo;
            String errMsg;
            String locModulus = OracleJavaSecure.getLocRSAPubMod();
            String locExponent = OracleJavaSecure.getLocRSAPubExp();
            // If you have a Secure Application Role, execute to set that here
            //stmt = ( OracleCallableStatement )conn.prepareCall(
            //    "CALL APPSCHEMA.p_check_APPSCHEMAview_access()" );
            //stmt.executeUpdate();
            //if( null != stmt ) stmt.close();


            // This section of code demonstrates how to exchange encryption keys
            // Do this before you try to do any encrypted data Inserts / Updates
            // Note: this process also happens whenever you do encrypted data queries
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL APPSCHEMA.APPSCHEMA_SEC_PKG.p_get_shared_passphrase(?,?,?,?,?,?,?,?)" );
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
                System.out.println( "Oracle error in Get Passphrase: " + errNo +
                    ", " + errMsg );
                System.out.println( (stmt.getRAW( 6 )).toString() );
            } else {
                sessionSecretDESSalt = stmt.getRAW( 3 );
                sessionSecretDESIterationCount = stmt.getRAW( 4 );
                sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                OracleJavaSecure.makeDESKey( sessionSecretDESPassPhrase,
                    sessionSecretDESAlgorithm, sessionSecretDESSalt,
                    sessionSecretDESIterationCount );
            }
            if( null != stmt ) stmt.close();


            // This section of code demonstrates how to query your data
            // to return sensitive columns in encrypted form
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL APPSCHEMA.APPSCHEMA_SEC_PKG.p_select_APPTABLE_sensitive(?,?,?,?,?,?,?,?,?)" );
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
                System.out.println( "Oracle error in Select: " + errNo +
                    ", " + errMsg );
            } else {
                sessionSecretDESSalt = stmt.getRAW( 3 );
                sessionSecretDESIterationCount = stmt.getRAW( 4 );
                sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                while( rs.next() ) {
                    System.out.print( rs.getString( 1 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 2 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 3 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 4 ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 5 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 6 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( "\n" );
                }
            }
            if( null != rs ) rs.close();
            if( null != stmt ) stmt.close();


            // This section of code demonstrates how to query your data where a
            // column has a specific value, to return sensitive in encrypted form
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL APPSCHEMA.APPSCHEMA_SEC_PKG.p_select_APPTABLE_by_COLUMN1_sens(?,?,?,?,?,?,?,?,?,?)" );
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
            stmt.setInt(   10, "SampleColumn1Value" );
            stmt.executeUpdate();
            errNo = stmt.getInt( 8 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 9 );
                System.out.println( "Oracle error in Select by Col: " + errNo +
                    ", " + errMsg );
            } else {
                sessionSecretDESSalt = stmt.getRAW( 3 );
                sessionSecretDESIterationCount = stmt.getRAW( 4 );
                sessionSecretDESAlgorithm = stmt.getRAW( 5 );
                sessionSecretDESPassPhrase = stmt.getRAW( 6 );
                rs = ( OracleResultSet )stmt.getCursor( 7 );
                while( rs.next() ) {
                    System.out.print( rs.getString( 1 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 2 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 3 ) );
                    System.out.print( ", " );
                    System.out.print( rs.getString( 4 ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 5 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( ", " );
                    System.out.print( OracleJavaSecure.getDecryptData(
                        rs.getRAW( 6 ), sessionSecretDESPassPhrase,
                        sessionSecretDESAlgorithm, sessionSecretDESSalt,
                        sessionSecretDESIterationCount ) );
                    System.out.print( "\n" );
                }
            }
            if( null != stmt ) stmt.close();

            
            // This section of code inserts / updates data, sending sensitive
            // data to Oracle in encrypted form
            // Executes Insert first time, Update thereafter
            // Assumes your session has already exchanged keys
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "call APPSCHEMA.APPSCHEMA_SEC_PKG.p_update_APPTABLE_sensitive(?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 12, OracleTypes.NUMBER );
            stmt.registerOutParameter( 13, OracleTypes.VARCHAR );
            stmt.setString( 1, "SampleCol1Value" );
            stmt.setString( 2, "SampleCol2Value" );
            stmt.setString( 3, "SampleCol3Value" );
            stmt.setString( 4, "SampleCol4Value" );
            stmt.setRAW(    5, OracleJavaSecure.getCryptData( "SampleCol5Value" ) );
            stmt.setRAW(    6, OracleJavaSecure.getCryptData( "SampleCol6Value" ) );
            stmt.setInt(    7, 0 );
            stmt.setNull(   8, OracleTypes.VARCHAR );
            stmt.executeUpdate();
            errNo = stmt.getInt( 12 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 13 );
                System.out.println( "Oracle error in Update: " + errNo + ", " + errMsg );
            }
            else System.out.println( "Oracle Update success!" );
            if( null != stmt ) stmt.close();

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
