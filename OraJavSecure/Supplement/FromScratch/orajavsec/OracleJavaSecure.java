//CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED appsec."orajavsec/OracleJavaSecure" AS
// First
//      SET ROLE APPSEC_ROLE;
// Also having ampersands in the code without substitution variables
//      SET DEFINE OFF;
// To run in Oracle, search for and comment @Suppress

// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12

package orajavsec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import java.lang.reflect.Method;

import java.math.BigInteger;

import java.net.URL;

import java.security.interfaces.RSAPublicKey;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import oracle.jdbc.driver.OracleDriver;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleTypes;

import oracle.jdbc.OracleResultSet;

import oracle.sql.RAW;
import oracle.sql.BLOB;

/*
 * OracleJavaSecure class sits at both ends of the client/server conversation
 * providing encryption / decryption and other functions
 */
public class OracleJavaSecure {
    // isTesting allows us to cache new 2-Factor Auth Code, even when
    // distribution is not available
    private static boolean isTesting = true;
    // Client To Server OK Status Flag
    private static String okReturnS = "return";

    private static String expectedDomain = "ORGDOMAIN";
    private static String comDomain = "org.com";
    private static String smtpHost = "smtp." + comDomain;
    private static String baseURL =
        "http://www.org.com/servlet/textpage.PageServlet?ACTION=2&PAGERID=";

    private static final int USE_PAGER = 1;
    private static final int USE_SMS = 2;
    private static final int USE_EMAIL = 4;

    // Assure you keep this private
    // cannot see the connection strings outside this static runtime class!
    // Assure all keys are in upper case - case sensitive matching
    // Only decrypt elements as needed
    private static HashMap<String, RAW> connsHash = null;

    // Everything is static - one value per virtual machine (one VM per session)
    private static SecureRandom random = new SecureRandom();
    private static Cipher cipherRSA;
    static {
        try {
            cipherRSA = Cipher.getInstance( "RSA" );
        } catch( Exception x ) {}
    }
    private static int twoFactorLength = 14;
    private static char[] twoFactorAuthChars = null;
    private static int keyLengthRSA = 1024;
    private static Cipher cipherDES;
    private static final int SALT_LENGTH = 8;
    private static Key locRSAPrivKey;
    private static RSAPublicKey locRSAPubKey;
    private static BigInteger locRSAPubMod = null;
    private static BigInteger locRSAPubExp;
    private static String saveExtRSAPubMod = null;
    private static RSAPublicKey extRSAPubKey = null;
    private static int maxPassPhraseBytes;
    private static char[] sessionSecretDESPassPhraseChars = null;
    private static SecretKey sessionSecretDESKey = null;
    // Note that PBEWithSHA1AndDESede is stronger encryption which should be
    //  implemented as soon as the Oracle JVM is updated to JDK 1.6 or later;
    //  but for now, the version of JDK 1.5 in Oracle JVM manifests this bug:
    //  http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6332761,
    //  "PBE SecretKeys are hard coded to return PBEWithMD5AndDES
    //  regardless of factory algorithm"
    // We will request PBEWithSHA1AndDESede on the server when we create the
    //  DES key, but will query the algorithm actually used
    //  and use that algorithm on the client in makeSessionSecretDESKey()
    // The cipher that will be used, for now, is PBEWithMD5AndDES
    //  both of these algorithms uses Cipher Block Chaining (CBC) as their mode
    private static String sessionSecretDESAlgorithm = "PBEWithSHA1AndDESede";
    private static byte[] salt;
    private static int iterationCount;
    private static AlgorithmParameterSpec paramSpec;
    // On the client, this connection is for a session and is not normally closed
    // For use with Oracle servers that limit connection time, may need to test
    // and renew this connection periodically
    // On the Oracle server, you should never close() the default connection
    // it never needs to be renewed
    private static OracleConnection conn;
    // This default connection is used on server side (java stored procedure)
    // You may also find an occassion to write error trapping / troubleshooting
    // data from the java running in the database server
    static {
        try {
            // The following throws an exception when running on workstation
            conn = (OracleConnection)(new OracleDriver().defaultConnection());
        } catch( Exception x ) {}
    }

    // When null, no key exchange for appver connection
    private static OracleConnection appVerConn = null;
    // Members to retain DES key for Connection String decryption
    private static byte[] appAuthSalt;
    private static int appAuthIterationCount;
    private static char[] appAuthDESPassPhraseChars;
    private static AlgorithmParameterSpec appAuthParamSpec;
    private static String appAuthSessionSecretDESAlgorithm;
    private static SecretKey appAuthSessionSecretDESKey;
    private static Cipher appAuthCipherDES;

    private static String applicationID = null;
    private static Object appClass      = null;
    private static String twoFactorAuth = null;

    public static final void setAppContext( String applicationID,
        Object appClass, String twoFactorAuth )
    {
        twoFactorAuth = checkFormat2Factor( twoFactorAuth );
        if( null == applicationID || null == appClass ) {
            System.out.println( "Must have an application ID and Class" );
            return;
        }
        // Assure the app class has implemented our interface
        if ( !( ( appClass instanceof RevLvlClassIntfc ) &&
            ( appClass instanceof Serializable ) ) )
        {
            System.out.println(
                "Application ID Class must implement RevLvlClassIntfc" );
            return;
        }
        // Set class static members equal to what passed here at outset
        OracleJavaSecure.applicationID = applicationID;
        OracleJavaSecure.appClass      = appClass;
        OracleJavaSecure.twoFactorAuth = twoFactorAuth;
    }

    /**
     * Create 2-Factor Auth Code and Distribute to available channels
     * Return code indicating which channels used
     * This is called as a Java Stored procedure on the Oracle server
     */
    public static final String distribute2Factor( String osUser, String applicationID )
        throws Exception
    {
        // Set class static member equal to what passed here from Oracle
        OracleJavaSecure.applicationID = applicationID;

        // Do not resend this two-factor authentication code,
        //  nor a new one using this session - unnecessary precaution
        if ( twoFactorAuthChars != null ) return "0";
        int distribCode = 0;
        OracleCallableStatement stmt = null;
        int errNo;
        String errMsg;
        try {
            twoFactorAuthChars = new char[twoFactorLength];
            for ( int i = 0; i < twoFactorLength; i++ ) {
                // Use numeric only to accommodate old pagers
                twoFactorAuthChars[i] = ( char )( random.nextInt( 58 - 48 ) + 48 );
                // Insert dashes (after every 4 characters) for readability
                if( 0 == ( ( i + 2 ) % 5 ) ) {
                    i++;
                    if ( i < twoFactorLength )
                        twoFactorAuthChars[i] = '-';
                }
            }
            twoFactorAuth = new String( twoFactorAuthChars );

            String oraFmtSt = "YYYY-MM-DD HH24:MI:SS"; // use with to_char()
            String javaFmtSt = "yyyy-MM-d H:m:s";
            SimpleDateFormat ora2JavaDtFmt = new SimpleDateFormat( javaFmtSt );

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_get_emp_2fact_nos(?,?,?,?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.NUMBER );
            stmt.registerOutParameter( 4, OracleTypes.VARCHAR );
            stmt.registerOutParameter( 5, OracleTypes.VARCHAR );
            stmt.registerOutParameter( 6, OracleTypes.VARCHAR );
            stmt.registerOutParameter( 7, OracleTypes.VARCHAR );
            stmt.registerOutParameter( 8, OracleTypes.VARCHAR );
            stmt.registerOutParameter( 9, OracleTypes.VARCHAR );
            stmt.registerOutParameter(10, OracleTypes.VARCHAR );
            stmt.registerOutParameter(12, OracleTypes.NUMBER );
            stmt.registerOutParameter(13, OracleTypes.VARCHAR );
            stmt.setString( 1, osUser );
            stmt.setString( 2, oraFmtSt );
            stmt.setInt(    3, 0 );
            stmt.setNull(   4, OracleTypes.VARCHAR );
            stmt.setNull(   5, OracleTypes.VARCHAR );
            stmt.setNull(   6, OracleTypes.VARCHAR );
            stmt.setNull(   7, OracleTypes.VARCHAR );
            stmt.setNull(   8, OracleTypes.VARCHAR );
            stmt.setNull(   9, OracleTypes.VARCHAR );
            stmt.setNull(  10, OracleTypes.VARCHAR );
            stmt.setString(11, applicationID );
            stmt.setInt(   12, 0 );
            stmt.setNull(  13, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 12 );
            if( errNo != 0 ) {
                // Error already logged from P_GET_EMP_2FACT_NOS
                errMsg = stmt.getString( 13 );
                stmt.executeUpdate(
                    "CALL app_sec_pkg.p_log_error( 0, '" +
                    "appsec.appsec_only_pkg.p_get_emp_2fact_nos: " +
                    errNo + ", " + errMsg + "' )" );
            } else {
                int    empID      = stmt.getInt( 3 );
                String pagerNo    = stmt.getString( 4 );
                String smsNo      = stmt.getString( 5 );
                String smsURL     = stmt.getString( 6 );
                String eMail      = stmt.getString( 7 );
                String ipAddress  = stmt.getString( 8 );
                String cTimeStamp = stmt.getString( 9 );
                String cIPAddr    = stmt.getString(10 );
                if( null != stmt ) stmt.close();

                // if cTimeStamp is null, no existing 2-Factor for user
                if( cTimeStamp != null ) try {
                    // Ten minutes ago Date
                    Date tmaDate = new Date( (new Date()).getTime() - 10*60*1000 );
                    Date cacheDate = ora2JavaDtFmt.parse( cTimeStamp );
                    // If user coming from same IP Address within 10 minutes
                    // do not distribute Code (will overwrite code from a new IP Addr)
                    if( ipAddress.equals( cIPAddr ) && cacheDate.after( tmaDate ) )
                        return "0";
                } catch( Exception z ) {
                    // How to handle error in these calculations?
                    return "0";
                }

                // Do distributions
                if( ( smsNo != null ) && ( !smsNo.equals( "" ) ) &&
                    ( smsURL != null ) && ( !smsURL.equals( "" ) )
                )
                    distribCode += distribToSMS( smsNo, smsURL );
                if( ( pagerNo != null ) && ( !pagerNo.equals( "" ) ) )
                    distribCode += distribToPagerURL( pagerNo );
                // Recommend not send to e-mail unless no other distrib option succeeds
                if( ( distribCode == 0 ) &&
                    ( eMail != null ) && ( !eMail.equals( "" ) )
                )
                    distribCode += distribToEMail( eMail );

                if( distribCode > 0 || isTesting ) {
                    stmt = ( OracleCallableStatement )conn.prepareCall(
                        "CALL appsec.appsec_only_pkg.p_update_2fact_cache(?,?,?,?,?,?)" );
                    stmt.registerOutParameter( 5, OracleTypes.NUMBER );
                    stmt.registerOutParameter( 6, OracleTypes.VARCHAR );
                    stmt.setInt(    1, empID );
                    stmt.setString( 2, applicationID );
                    stmt.setString( 3, twoFactorAuth );
                    stmt.setString( 4, String.valueOf( distribCode ) );
                    stmt.setInt(    5, 0 );
                    stmt.setNull(   6, OracleTypes.VARCHAR );
                    stmt.executeUpdate();

                    errNo = stmt.getInt( 5 );
                    if( errNo != 0 ) {
                        // Error already logged from P_UPDATE_2FACT_CACHE
                        errMsg = stmt.getString( 6 );
                        stmt.executeUpdate(
                            "CALL app_sec_pkg.p_log_error( 0, '" +
                            "appsec.appsec_only_pkg.p_update_2fact_cache: " +
                            errNo + ", " + errMsg + "' )" );
                    }
                }
            }
        } catch( Exception x ) {
            java.io.CharArrayWriter errorText = new java.io.CharArrayWriter( 4000 );
            x.printStackTrace( new java.io.PrintWriter( errorText ) );
            stmt.executeUpdate( "CALL app_sec_pkg.p_log_error( 0, '" +
                errorText.toString() + "' )" );
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return String.valueOf( distribCode );
    }


    // This is an administrative function - do not give client access
    // Sets or overwrites a connection string
    public static void putAppConnString( String instance, String user,
        String password, String host, String port )
    {
        putAppConnString( instance, user, password, host, port, false );
    }
    public static String putAppConnString( String instance, String user,
        String password, String host, String port, boolean testFirst )
    {
        String rtrnString = "";
        instance = instance.trim();
        user = user.trim();
        password = password.trim();
        host = host.trim();
        port = port.trim();
        String key = (instance + "/" + user).toUpperCase();
        String connS = "jdbc:oracle:thin:" + user + "/" + password + "@" +
            host + ":" + port + ":" + instance;
        boolean testSuccess = true;
        if( testFirst ) {
            Connection mConn = null;
            try {
                mConn = DriverManager.getConnection( connS );
                Statement stmt = mConn.createStatement();
                ResultSet rs = stmt.executeQuery(
                    "SELECT SYSDATE FROM DUAL" );
                System.out.println("Connection string successful");
                rtrnString += "Connection string successful";
            } catch (Exception x) {
                System.out.println("Connection string failed!");
                rtrnString += "Connection string failed";
                testSuccess = false;
            } finally {
                try {
                    if( null != mConn ) mConn.close();
                } catch( Exception x ) {}
            }
        }
        if( testSuccess ) {
            try {
                appAuthCipherDES.init( Cipher.ENCRYPT_MODE,
                    appAuthSessionSecretDESKey, appAuthParamSpec );
                byte[] bA = appAuthCipherDES.doFinal( connS.getBytes() );
                connsHash.put(key, new RAW( bA ) );
            } catch( Exception x ) {}
        }
        return rtrnString;
    }


    // This is an administrative function - do not give client access
    // Must have already exchanged keys, because sending conn strings
    // to Oracle encrypted with DES secret password key
    public static void putAppConnections(){
        OracleCallableStatement stmt = null;
        try {
            if( null == appVerConn ) {
                if( null == conn ) {
                    System.out.println( "Call getAppConnections to establish " +
                        "connection to AppVer first, " +
                        "else can not putAppConnections!" );
                } else {
                    System.out.println( "Connection to AppVer overwritten - " +
                        "can not putAppConnections!" );
                }
                return;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oout = new ObjectOutputStream( baos );
            oout.writeObject( appClass );
            oout.flush();
            oout.close();
            byte[] appClassBytes = baos.toByteArray();
            baos.close();

            baos = new ByteArrayOutputStream();
            oout = new ObjectOutputStream( baos );
            oout.writeObject( connsHash );
            oout.flush();
            oout.close();
            byte[] connsHashBytes = baos.toByteArray();
            baos.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "{? = call appsec.appsec_admin_pkg.f_set_decrypt_conns(?,?)}" );
            stmt.registerOutParameter( 1, OracleTypes.VARCHAR );
            stmt.setBytes( 2, appClassBytes );
            stmt.setBytes( 3, connsHashBytes );
            stmt.executeUpdate();

            String checkReturn = stmt.getString( 1 );
            if( ! checkReturn.equals( okReturnS ) )
                System.out.println( "from f_set_decrypt_conns: " + checkReturn );
        } catch ( Exception x ) {
            x.printStackTrace();
        } finally {
            try {
                if ( null != stmt )
                    stmt.close();
            } catch ( Exception y ) {}
        }
    }

    static String location = "in setAppVerConnection method.";
    public static String l = location;
    private static void setAppVerConnection() {
        try {
            // Set this String from encoded String at command prompt (main)
            String prime =
"030a42105f1b3311133a0048370707005f020419190b524215151b1c13411b0a044225182e13113a0d1d301b545f505145530e1e560817";
			setConnection( OJSC.y( prime ) );
            appVerConn = conn;
        } catch( Exception x ) {
            x.printStackTrace();
        }
    }


    //@SuppressWarnings( "unchecked" )
    public static String setDecryptConns( RAW classInstance, RAW connections ) {
        String rtrnString = okReturnS;
        OracleCallableStatement stmt = null;
        try {
            /*
            // Example debug log entry for java stored procedure
            // Assure not in middle of existing stmt processing
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "call APP_SEC_PKG.P_LOG_ERROR( 0, '" +
                    "setdecryptconns called!' )" );
            stmt.executeUpdate();
            */

            byte[] appClassBytes = classInstance.getBytes();
            ByteArrayInputStream bAIS = new ByteArrayInputStream( appClassBytes );
            ObjectInputStream oins =
                new ObjectInputStream( bAIS );
            Object classObject = oins.readObject();
            oins.close();
            Class providedClass = classObject.getClass();

            String className = providedClass.getName();
            Method classMethod = providedClass.getMethod( "getRevLvl" );
            String classVersion = ( String )classMethod.invoke( classObject );

            // Do this once we get to Oracle
            // Before we store any class, let us assure it has a package (.)
            // noted before being an inner class ($) - our planned requirements
            if( -1 == className.indexOf( "." ) ||
                className.indexOf( "$" ) < className.indexOf( "." ) )
                return "App class must be in a package and be an inner class!";

            // select count from table where name/version equal
            // if 0, insert, else overwrite
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_count_class_conns(?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.NUMBER );
            stmt.setString( 1, className );
            stmt.setString( 2, classVersion );
            stmt.setInt(    3, 0 );
            stmt.executeUpdate();
            if( stmt.getInt( 3 ) == 0 ) {
                // Do insert!
            } else {
                // Assure provided instance and cached, if same version, are equal
                // NOTE: handling BLOBs with getBytes and setBytes is new to 11g
                stmt = ( OracleCallableStatement )conn.prepareCall(
                    "CALL appsec.appsec_only_pkg.p_get_class_conns(?,?,?,?)" );
                stmt.registerOutParameter( 3, OracleTypes.RAW );
                stmt.registerOutParameter( 4, OracleTypes.BLOB );
                stmt.setString( 1, className );
                stmt.setString( 2, classVersion );
                stmt.setNull(   3, OracleTypes.RAW );
                stmt.setNull(   4, OracleTypes.BLOB );
                stmt.executeUpdate();

                byte[] cachedBytes = stmt.getBytes(3);
                oins = new ObjectInputStream( new ByteArrayInputStream(
                    cachedBytes ) );
                classObject = oins.readObject();
                oins.close();
                // Attempting to instantiate 2 different classes with the same
                // name will throw an InvalidClassException - further tests
                // not really required.
                Class testClass = classObject.getClass();

                // Saying that these classes are equal is the supreme test!
                //if( testClass.equals( providedClass ) ) {
                if( testClass == providedClass ) {
                    /*
                    // byte for byte comparison does not improve on equals
                    try {
                        // compares each byte for length of classBytes,
                        // also test on equal length, below
                        boolean exactMatch = true;
                        for ( int i = 0; i < appClassBytes.length; i++ ) {
                            if ( appClassBytes[i] != cachedBytes[i] ) {
                                exactMatch = false;
                                break;
                            }
                        }
                        if( ! exactMatch ) return "Failed to setDecryptConns";
                    } catch ( Exception z ) {
                        return "Failed to setDecryptConns";
                    }
                    */
                } else return "Failed to setDecryptConns";
            }
            oins = new ObjectInputStream( new ByteArrayInputStream(
                connections.getBytes() ) );
            classObject = oins.readObject();
            oins.close();
            HashMap<String, RAW> cryptConnsHash =
                (HashMap<String, RAW>)classObject;
            HashMap<String, String> clearConnsHash =
                new HashMap<String, String>();
            // This try/catch added to allow register new app class from Admin GUI
            try {
                cipherDES.init( Cipher.DECRYPT_MODE, sessionSecretDESKey, paramSpec );
                for( String key : cryptConnsHash.keySet() ) {
                    // Decrypt each one
                    clearConnsHash.put( key,
                        new String(
                            cipherDES.doFinal(
                                (cryptConnsHash.get( key )).getBytes()
                            )
                        )
                    );
                }
           } catch( Exception z ){
                // Allow for null sessionSecretDESKey
           }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oout = new ObjectOutputStream( baos );
            oout.writeObject( clearConnsHash );
            oout.flush();
            oout.close();
            byte[] connsHashBytes = baos.toByteArray();
            baos.close();

            // Mask the Connections before storing on disk
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "{? = call appsec.f_mask(?,?,?)}" );
            stmt.registerOutParameter( 1, OracleTypes.RAW );
            stmt.setBytes(  2, connsHashBytes );
            stmt.setString( 3, className );
            stmt.setString( 4, classVersion );
            stmt.executeUpdate();
            connsHashBytes = stmt.getBytes(1);

            // NOTE: handling BLOBs with getBytes and setBytes is new to Oracle 11g
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_set_class_conns(?,?,?,?)" );
            stmt.setString( 1, className );
            stmt.setString( 2, classVersion );
            stmt.setBytes(  3, appClassBytes );
            stmt.setBytes(  4, connsHashBytes );
            stmt.executeUpdate();
        /*
        } catch ( java.io.InvalidClassException w ) {
            // This is thrown when the serialVersionUID of the class is different
            // from what is expected
            // when class has changed in significant ways from what was stored
            // cannot instantiate the class based on the stored object
        */
        } catch ( Exception x ) {
            try {
                rtrnString = x.toString();
                java.io.CharArrayWriter errorText = new java.io.CharArrayWriter( 10000 );
                x.printStackTrace( new java.io.PrintWriter( errorText ) );
                stmt.executeUpdate( "CALL app_sec_pkg.p_log_error( 0, '" +
                    errorText.toString() + "' )" );
            } catch ( Exception y ) {}
        } finally {
            try {
                if ( null != stmt )
                    stmt.close();
            } catch ( Exception y ) {}
        }
        return rtrnString;
    }

    // Called from java stored procedure
    //@SuppressWarnings( "unchecked" )
    public static String copyPreviousConns( RAW classInstance, String prevVersion ) {
        String rtrnString = "function";
        OracleCallableStatement stmt = null;
        try {
            byte[] appClassBytes = classInstance.getBytes();
            ByteArrayInputStream bAIS = new ByteArrayInputStream( appClassBytes );
            ObjectInputStream oins =
                new ObjectInputStream( bAIS );
            Object classObject = oins.readObject();
            oins.close();
            Class providedClass = classObject.getClass();

            String className = providedClass.getName();
            Method classMethod = providedClass.getMethod( "getRevLvl" );
            String classVersion = ( String )classMethod.invoke( classObject );

            // class and connsHash from previous version
            // if null, return, nothing to copy
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_get_class_conns(?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.BLOB );
            stmt.setString( 1, className );
            stmt.setString( 2, prevVersion );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.BLOB );
            stmt.executeUpdate();
            if( null == stmt.getBytes( 3 ) ) return "Nothing to copy";

            // Unmask the previous Connections when reading from disk
            byte[] prevConnsBytes = stmt.getBytes(4);
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "{? = call appsec.f_unmask(?,?,?)}" );
            stmt.registerOutParameter( 1, OracleTypes.RAW );
            stmt.setBytes(  2, prevConnsBytes );
            stmt.setString( 3, className );
            stmt.setString( 4, prevVersion );
            stmt.executeUpdate();

            prevConnsBytes = stmt.getBytes(1);
            // We need not get a HashMap object of previous connections
            // will be saving bytes directly for new version
            //oins = new ObjectInputStream( new ByteArrayInputStream(
            //    prevConnsBytes ) );
            //Object previousConns = oins.readObject();
            //oins.close();


            // select count from table where name/version equal
            // if 0, insert, else overwrite
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_count_class_conns(?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.NUMBER );
            stmt.setString( 1, className );
            stmt.setString( 2, classVersion );
            stmt.setInt(    3, 0 );
            stmt.executeUpdate();
            boolean okToOverwrite = false;
            if( stmt.getInt( 3 ) == 0 ) {
                // Do insert!
                okToOverwrite = true;
            } else {
                // Assure provided instance and cached, if same version, are equal
                // NOTE: handling BLOBs with getBytes and setBytes is new to 11g
                stmt = ( OracleCallableStatement )conn.prepareCall(
                    "CALL appsec.appsec_only_pkg.p_get_class_conns(?,?,?,?)" );
                stmt.registerOutParameter( 3, OracleTypes.RAW );
                stmt.registerOutParameter( 4, OracleTypes.BLOB );
                stmt.setString( 1, className );
                stmt.setString( 2, classVersion );
                stmt.setNull(   3, OracleTypes.RAW );
                stmt.setNull(   4, OracleTypes.BLOB );
                stmt.executeUpdate();

                byte[] cachedBytes = stmt.getBytes(3);
                oins = new ObjectInputStream( new ByteArrayInputStream(
                    cachedBytes ) );
                classObject = oins.readObject();
                oins.close();
                // Attempting to instantiate 2 different classes with the same
                // name will throw an InvalidClassException - further tests
                // not really required.
                Class testClass = classObject.getClass();

                // Saying that these classes are equal is the supreme test!
                //if( ! testClass.equals( providedClass ) )
                if( testClass != providedClass )
                    return "Failed to setDecryptConns";

                if( null == stmt.getBytes(4) ) okToOverwrite = true;
                else {
                    // Unmask the current Connections when reading from disk
                    byte[] connsBytes = stmt.getBytes(4);
                    stmt = ( OracleCallableStatement )conn.prepareCall(
                        "{? = call appsec.f_unmask(?,?,?)}" );
                    stmt.registerOutParameter( 1, OracleTypes.RAW );
                    stmt.setBytes(  2, connsBytes );
                    stmt.setString( 3, className );
                    stmt.setString( 4, classVersion );
                    stmt.executeUpdate();

                    oins = new ObjectInputStream( new ByteArrayInputStream(
                        stmt.getBytes(1) ) );
                    Object currentConns = oins.readObject();
                    oins.close();
                    HashMap<String, String> currConnsHash =
                        (HashMap<String, String>)currentConns;
                    if( 0 == currConnsHash.size() ) okToOverwrite = true;
                }
            }
            if( ! okToOverwrite ) return "Current connsHash is not empty!";

            // Mask the Connections before storing on disk
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "{? = call appsec.f_mask(?,?,?)}" );
            stmt.registerOutParameter( 1, OracleTypes.RAW );
            stmt.setBytes(  2, prevConnsBytes );
            stmt.setString( 3, className );
            stmt.setString( 4, classVersion );
            stmt.executeUpdate();
            prevConnsBytes = stmt.getBytes(1);

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_set_class_conns(?,?,?,?)" );
            stmt.setString( 1, className );
            stmt.setString( 2, classVersion );
            stmt.setBytes(  3, appClassBytes );
            stmt.setBytes(  4, prevConnsBytes );
            stmt.executeUpdate();
        } catch ( Exception x ) {
            try {
                java.io.CharArrayWriter errorText = new java.io.CharArrayWriter( 4000 );
                x.printStackTrace( new java.io.PrintWriter( errorText ) );
                stmt.executeUpdate( "CALL app_sec_pkg.p_log_error( 0, '" +
                    errorText.toString() + "' )" );
            } catch ( Exception y ) {}
        } finally {
            try {
                if ( null != stmt )
                    stmt.close();
            } catch ( Exception y ) {}
        }
        return rtrnString;
    }

    //
    public static OracleConnection getAAConnRole( String instance, String userName ) {
        OracleConnection mConn = null;
        OracleCallableStatement stmt = null;
        try {
            mConn = getAppAuthConn( instance, userName );
            // If mConn is null, probably did not send twoFactorAuth
            if( null == mConn ) return mConn;
            int errNo;
            String errMsg;
            stmt = ( OracleCallableStatement )mConn.prepareCall(
                "CALL appsec.p_check_role_access(?,?,?)" );
                stmt.registerOutParameter( 2, OracleTypes.NUMBER );
                stmt.registerOutParameter( 3, OracleTypes.VARCHAR );
                stmt.setString( 1, applicationID );
                stmt.setInt(    2, 0 );
                stmt.setNull(   3, OracleTypes.VARCHAR );
            stmt.executeUpdate();
            errNo = stmt.getInt( 2 );
            errMsg = stmt.getString( 3 );
            //System.out.println( "DistribCd = " + errMsg );
            if( errNo != 0 ) {
                System.out.println( "Oracle error 1) " + errNo + ", " + errMsg );
            } else if( twoFactorAuth.equals( "" ) ) {
                System.out.println( "Call again with 2-Factor code parameter" );
            }
        } catch ( Exception x ) {
            x.printStackTrace();
        } finally {
            try {
                if( null != stmt ) stmt.close();
            } catch( Exception y ) {}
        }
        return mConn;
    }

    // Decrypt Connection String to instantiate Connection and return
    // Do not store decrypted String!
    // Called on client to get specific connection String
    // Can only provide connections that are authorized to proxy through
    // Either APPVER or the specific user registered for the application
    private static OracleConnection getAppAuthConn( String instance, String userName ) {
        OracleConnection mConn = null;
        try {
            if( null == connsHash ) getAppConnections();
            // If we entered without twoFactorAuth, apAuth...DESKey is null
            if( null == appAuthSessionSecretDESKey ) return mConn;
            instance = instance.trim();
            userName = userName.trim();
            String key = ( instance + "/" + userName ).toUpperCase();
            // Bananas - for my daughter, Lydia
            appAuthCipherDES.init( Cipher.DECRYPT_MODE, appAuthSessionSecretDESKey,
                appAuthParamSpec );
            mConn = setConnection( new String( appAuthCipherDES.doFinal(
                connsHash.get( key ).getBytes() ) ) );
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        return mConn;
    }


    // Annotation suppresses warnings about ClassCastException
    // Called on client to retrieve connections for application from Oracle
    // No annotations on Oracle server
    //@SuppressWarnings( "unchecked" )
    public static void getAppConnections() {
        OracleCallableStatement stmt = null;
        try {
            if( null == appVerConn ) setAppVerConnection();

            int errNo;
            String errMsg;

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oout = new ObjectOutputStream( baos );
            oout.writeObject( appClass );
            oout.flush();
            oout.close();
            byte[] appClassBytes = baos.toByteArray();
            baos.close();

            String locModulus = OracleJavaSecure.getLocRSAPubMod();
            String locExponent = OracleJavaSecure.getLocRSAPubExp();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_public_pkg.p_get_app_conns(?,?,?,?,?,?,?,?,?,?,?,?)" );
            stmt.registerOutParameter( 5, OracleTypes.RAW );
            stmt.registerOutParameter( 6, OracleTypes.RAW );
            stmt.registerOutParameter( 7, OracleTypes.RAW );
            stmt.registerOutParameter( 8, OracleTypes.RAW );
            stmt.registerOutParameter( 9, OracleTypes.RAW );
            stmt.registerOutParameter(11, OracleTypes.NUMBER );
            stmt.registerOutParameter(12, OracleTypes.VARCHAR );
            stmt.setString( 1, locModulus );
            stmt.setString( 2, locExponent );
            stmt.setString( 3, twoFactorAuth );
            // Either method works for setting RAW
            //stmt.setRAW(    4, new RAW( appClassBytes ) );
            stmt.setBytes(  4, appClassBytes );
            stmt.setNull(   5, OracleTypes.RAW );
            stmt.setNull(   6, OracleTypes.RAW );
            stmt.setNull(   7, OracleTypes.RAW );
            stmt.setNull(   8, OracleTypes.RAW );
            stmt.setNull(   9, OracleTypes.RAW );
            stmt.setString(10, applicationID );
            stmt.setInt(   11, 0 );
            stmt.setNull(  12, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 11 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 12 );
                System.out.println( "Oracle error 21) " + errNo +
                    ", " + errMsg );
            } else {
                if( stmt.getRAW( 9 ) == null ) {
                    System.out.println( "Please rerun with 2-Factor Auth Code!" );
                    return;
                }
                // This block certainly needs to be done or we are out of order;
                // however, for self-assurance, test first.
                if( null == sessionSecretDESKey ) {
                    makeDESKey( stmt.getRAW( 9 ), stmt.getRAW( 8 ),
                        stmt.getRAW( 6 ), stmt.getRAW( 7 ) );
                    // Cant just set new pointers to existing members
                    // Since static, updates to one will update both
                    // Must instantiate, clone or copy values
                    appAuthSalt = salt.clone();
                    appAuthIterationCount =
                        (new Integer( iterationCount )).intValue();
                    appAuthDESPassPhraseChars =
                        sessionSecretDESPassPhraseChars.clone();
                    appAuthParamSpec = new PBEParameterSpec( appAuthSalt,
                        appAuthIterationCount );
                    KeySpec keySpec = new PBEKeySpec( appAuthDESPassPhraseChars,
                        appAuthSalt, appAuthIterationCount );
                    appAuthSessionSecretDESAlgorithm =
                        new String( sessionSecretDESAlgorithm );
                    appAuthSessionSecretDESKey = SecretKeyFactory.getInstance(
                        appAuthSessionSecretDESAlgorithm ).generateSecret( keySpec );
                    appAuthCipherDES = Cipher.getInstance(
                        appAuthSessionSecretDESKey.getAlgorithm() );
                    resetKeys();
                }

                // Exception will be thrown if no HashMap exists for appClass
                // In that case, return a new, empty HashMap
                Object classObject = null;
                try {
                    ObjectInputStream oins =
                        new ObjectInputStream( new ByteArrayInputStream(
                        stmt.getBytes( 5 ) ) );
                    classObject = oins.readObject();
                    oins.close();
                } catch( Exception y ) {}
                if( classObject != null ) {
                    connsHash = (HashMap<String, RAW>)classObject;
                } else {
                    connsHash = new HashMap<String, RAW>();
                }
            }
        } catch ( Exception x ) {
            x.printStackTrace();
        } finally {
            try {
                if ( null != stmt )
                    stmt.close();
            } catch ( Exception y ) {
            }
        }
    }

    // Called from Oracle java stored procedures
    // Get HashMap of unencrypted Strings, encrypt and build new HashMap
    // Annotation suppresses warnings about ClassCastException
    // Annotation suppresses warnings about blind method call
    // No annotations on Oracle
    //@SuppressWarnings( "unchecked" )
    public static RAW getCryptConns( RAW classInstance ) {
        RAW rtrnRAW = null;
        OracleCallableStatement stmt = null;
        try {
            /*
            // Example debug log entry for java stored procedure
            // Assure not in middle of existing stmt processing
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "call APP_SEC_PKG.P_LOG_ERROR( 0, '" +
                    "getcryptconns called!' )" );
            stmt.executeUpdate();
            */

            byte[] bA = classInstance.getBytes();
            ByteArrayInputStream bAIS = new ByteArrayInputStream( bA );
            ObjectInputStream oins =
                new ObjectInputStream( bAIS );
            Object classObject = oins.readObject();
            oins.close();
            Class providedClass = classObject.getClass();
            String className = providedClass.getName();
            Method classMethod = providedClass.getMethod( "getRevLvl" );
            String classVersion = ( String )classMethod.invoke( classObject );

            // NOTE: handling BLOBs with getBytes and setBytes is new to 11g
            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_only_pkg.p_get_class_conns(?,?,?,?)" );
            stmt.registerOutParameter( 3, OracleTypes.RAW );
            stmt.registerOutParameter( 4, OracleTypes.BLOB );
            stmt.setString( 1, className );
            stmt.setString( 2, classVersion );
            stmt.setNull(   3, OracleTypes.RAW );
            stmt.setNull(   4, OracleTypes.BLOB );
            stmt.executeUpdate();
            if( null == stmt.getBytes(3) ) return null;
            oins = new ObjectInputStream( new ByteArrayInputStream(
                stmt.getBytes(3) ) );
            classObject = oins.readObject();
            oins.close();
            Class testClass = classObject.getClass();
            // Saying that these classes are equal is the supreme test!
            //if( testClass.equals( providedClass ) ) {
            if( testClass == providedClass ) {

                // Unmask the Connections when reading from disk
                bA = stmt.getBytes(4);
                stmt = ( OracleCallableStatement )conn.prepareCall(
                    "{? = call appsec.f_unmask(?,?,?)}" );
                stmt.registerOutParameter( 1, OracleTypes.RAW );
                stmt.setBytes(  2, bA );
                stmt.setString( 3, className );
                stmt.setString( 4, classVersion );
                stmt.executeUpdate();

                oins = new ObjectInputStream( new ByteArrayInputStream(
                    stmt.getBytes(1) ) );
                classObject = oins.readObject();
                oins.close();
                HashMap<String, String> clearConnsHash =
                    (HashMap<String, String>)classObject;
                HashMap<String, RAW> cryptConnsHash =
                    new HashMap<String, RAW>();
                cipherDES.init( Cipher.ENCRYPT_MODE, sessionSecretDESKey, paramSpec );
                for( String key : clearConnsHash.keySet() ) {
                    // Encrypt each one
                    cryptConnsHash.put( key,
                        new RAW(
                            cipherDES.doFinal(
                                (clearConnsHash.get( key )).getBytes()
                            )
                        )
                    );
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oout = new ObjectOutputStream( baos );
                oout.writeObject( cryptConnsHash );
                oout.flush();
                oout.close();
                rtrnRAW = new RAW( baos.toByteArray() );
                baos.close();
            }
        /*
        } catch ( java.io.InvalidClassException w ) {
            // This is thrown when the serialVersionUID of the class is different
            // from what is expected
            // when class has changed in significant ways from what was stored
            // cannot instantiate the class based on the stored object
        */
        } catch ( Exception x ) {
            try {
                java.io.CharArrayWriter errorText = new java.io.CharArrayWriter( 4000 );
                x.printStackTrace( new java.io.PrintWriter( errorText ) );
                stmt.executeUpdate( "CALL app_sec_pkg.p_log_error( 0, '" +
                    errorText.toString() + "' )" );
            } catch ( Exception y ) {}
        } finally {
            try {
                if ( null != stmt )
                    stmt.close();
            } catch ( Exception y ) {}
        }
        return rtrnRAW;
    }


    // This is an administrative function - do not give client access
    // Call putAppConnections after this to save changes in Oracle
    static void removeAppConnString( String instance, String user ) {
        instance = instance.trim();
        user = user.trim();
        String key = (instance + "/" + user).toUpperCase();
        connsHash.remove( key );
    }

    // This method is just used to check if we succeeded in 2-factor auth
    // connsHash will be null if we didnt
    public static boolean test2Factor() {
        try {
            connsHash.size();
        } catch( Exception x ) {
            return false;
        }
        return true;
    }

    static Vector listConnNames() {
        // Package protection - only for orajavsec classes like OJSAdmin
        Vector<String> rtrnV = new Vector<String>();
        try {
            for (String key : connsHash.keySet())
                rtrnV.add(key);
        } catch (Exception x) {
        }
        return rtrnV;
    }

    // This is an administrative function
    // Copies conn Strings from old version to new version (should be empty)
    // Derived this method from putAppConnections
    public static void copyAppConnections( String oldVersion ) {
        OracleCallableStatement stmt = null;
        try {
            // Not trimming or filtering oldVersion, because original

            if( null == appVerConn ) setAppVerConnection();

            int errNo;
            String errMsg;

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oout = new ObjectOutputStream( baos );
            oout.writeObject( appClass );
            oout.flush();
            oout.close();
            byte[] appClassBytes = baos.toByteArray();
            baos.close();

            stmt = ( OracleCallableStatement )conn.prepareCall(
                "CALL appsec.appsec_admin_pkg.p_copy_app_conns(?,?,?,?,?,?)" );
            stmt.registerOutParameter( 5, OracleTypes.NUMBER );
            stmt.registerOutParameter( 6, OracleTypes.VARCHAR );
            stmt.setString( 1, twoFactorAuth );
            stmt.setBytes(  2, appClassBytes );
            stmt.setString( 3, oldVersion );
            stmt.setString( 4, applicationID );
            stmt.setInt(    5, 0 );
            stmt.setNull(   6, OracleTypes.VARCHAR );
            stmt.executeUpdate();

            errNo = stmt.getInt( 5 );
            if( errNo != 0 ) {
                errMsg = stmt.getString( 6 );
                System.out.println( "Oracle error 23) " + errNo +
                    ", " + errMsg );
            }

        } catch ( Exception x ) {
            x.printStackTrace();
        } finally {
            try {
                if ( null != stmt )
                    stmt.close();
            } catch ( Exception y ) {}
        }
    }

    /**
     * Try Distribute 2-Factor Auth Code to SMS Phone
     */
    private static final int distribToSMS( String smsNo, String smsURL )
    {
        int distribCode = 0;
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.executeUpdate( "ALTER SESSION SET SMTP_OUT_SERVER = '" +
                smtpHost + "'" );
            stmt.executeUpdate( "CALL UTL_MAIL.SEND( 'response@" +
                comDomain + "', '" + smsNo + "@" + smsURL +
                "', '', '', 'Response for " + applicationID + "','" +
                twoFactorAuth + " for " + applicationID + "' )" );
            distribCode += USE_SMS;
        } catch ( Exception x ) {
            try {
                stmt.executeUpdate(
                    "CALL app_sec_pkg.p_log_error( 0, '" +
                    "Error in distribToSMS for " + smsNo + "@" + smsURL + "' )" );
            } catch( Exception y ) {}
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return distribCode;
    }

    /**
     * Try Distribute 2-Factor Auth Code to Pager via Web Server
     */
    private static final int distribToPagerURL( String pagerNo ) {
        int distribCode = 0;
        Statement stmt = null;
        try {
            // Assuming numeric-only pagers will truncate this message
            URL u = new URL( baseURL + pagerNo + "&MESSAGE=" + twoFactorAuth +
                " _for " + applicationID );
            u.getContent();
            distribCode += USE_PAGER;
        } catch ( Exception x ) {
            try {
                stmt = conn.createStatement();
                stmt.executeUpdate(
                    "CALL app_sec_pkg.p_log_error( 0, '" +
                    "Error in distribToPagerURL for " + pagerNo + "' )" );
            } catch( Exception y ) {}
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return distribCode;
    }

    /**
     * Try Distribute 2-Factor Auth Code to E-Mail
     */
    private static final int distribToEMail( String eMail )
    {
        int distribCode = 0;
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.executeUpdate( "ALTER SESSION SET SMTP_OUT_SERVER = '" +
                smtpHost + "'" );
            stmt.executeUpdate( "CALL UTL_MAIL.SEND( 'response@" +
                comDomain + "', '" + eMail + "@" + comDomain +
                "', '', '', 'Response for " + applicationID + "','" +
                twoFactorAuth + " for " + applicationID + "' )" );
            distribCode += USE_EMAIL;
        } catch ( Exception x ) {
            try {
                stmt.executeUpdate(
                    "CALL app_sec_pkg.p_log_error( 0, '" +
                    "Error in distribToEMail for " + eMail + "' )" );
            } catch( Exception y ) {}
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return distribCode;
    }

    /**
     * This was for Chapter 7 testing, now modified for Chapter 10 App Auth
     */
    public static final void resetKeys() {
        locRSAPubMod = null;
        saveExtRSAPubMod = null;
        extRSAPubKey = null;
        sessionSecretDESPassPhraseChars = null;
        // Do not set sessionSecretDESKey to null when progressing from APPVER
        // to other connections - disables encryption members
        //sessionSecretDESKey = null;
        sessionSecretDESAlgorithm = "PBEWithSHA1AndDESede";
    }

    /**
     * Called from Client Application set the Connection for use with this class
     * From here on out, use OracleConnection class instead of Connection class
     */
    private static final OracleConnection setConnection( String URL ) {
        Connection c = null;
        try {
            Class.forName( "oracle.jdbc.driver.OracleDriver" );
            c = DriverManager.getConnection( URL );
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        return setConnection( c );
    }
    private static final OracleConnection setConnection( Connection c )
    {
        return setConnection( (OracleConnection)c );
    }

	private static String osUserName = null;

    public static String getOSUserName() {
        return osUserName;
    }
  
  	public static boolean isAppverOK() {
      	if( appVerConn == null)
      		return false;
      	else return true;
  	}

    private static final OracleConnection setConnection( OracleConnection c )
    {
        conn = null;
        appVerConn = null;

        // We are going to require that only we will set up proxy connections
        if( c == null || c.isProxySession() ) return null;
        else try {
            // Set up a non-pooled proxy connection with Client Identifier
            // To use an alternate solution, refer to code in Chapter8/OraSSOTests.java
            osUserName = getOSUserID();
            if ( ( osUserName != null ) && ( !osUserName.equals( "" ) ) ) {
                Properties prop = new Properties();
                prop.setProperty( OracleConnection.PROXY_USER_NAME, osUserName );
                c.openProxySession(OracleConnection.PROXYTYPE_USER_NAME, prop);

                String metrics[] =
                    new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
                metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = osUserName;
                metrics[OracleConnection.END_TO_END_ACTION_INDEX] = twoFactorAuth;
                c.setEndToEndMetrics( metrics, ( short )0 );

                // If we do not get here, no Connection will be available
                conn = c;
            } else {
                System.out.println( "This is not a valid user!" );
            }
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        return conn;
    }


    /**
     * Called from Client Application to close the proxy connection
     */
    public static final void closeConnection() {
        try {
            conn.close( OracleConnection.PROXY_SESSION );
        } catch( Exception x ) {}
    }


    // A private constructor keeps everyone from instantiating this class
    // All methods and members are static
    private OracleJavaSecure() {
    }

    private static String getOSUserID() {
        String rtrnString = null;
        try {
            if ((System.getProperty("os.arch").equals("x86") ||
                System.getProperty("os.arch").endsWith("64")) &&
                System.getProperty("os.name").startsWith("Windows") )
            {
                Class mNTS = Class.forName( "com.sun.security.auth.module.NTSystem" );

                Method classMethod = mNTS.getMethod( "getDomain" );
                String domain = ( String )classMethod.invoke( mNTS.newInstance() );
                domain = domain.toUpperCase();

                classMethod = mNTS.getMethod( "getName" );
                String name = ( String )classMethod.invoke( mNTS.newInstance() );
                name = name.toUpperCase();

                //System.out.println( "Domain: " + domain + ", Name: " + name );
                if ( ( name != null ) && ( !name.equals( "" ) ) &&
                    ( domain != null ) &&
                    domain.equalsIgnoreCase( expectedDomain ) )
                {
                    rtrnString = name;
                } else {
                    System.out.println( "Expecting domain = " + expectedDomain );
                    System.out.println( "User " + name + " must exist in Oracle"  );
                }
            } else {
                // Assuming Unix
                Class mUX = Class.forName( "com.sun.security.auth.module.UnixSystem" );

                Method classMethod = mUX.getMethod( "getDomain" );
                String name = ( String )classMethod.invoke( mUX.newInstance() );
                name = name.toUpperCase();

                System.out.println( "Name: " + name  );
                if( ( name != null ) && ( ! name.equals( "" ) ) )
                {
                    rtrnString = name;
                }
            }
        } catch( Exception x ) {
            System.out.println( x.toString() );
        }
        return rtrnString;
    }

    /**
     * Called from Client Application when Key Exchange only
     */
    public static final void makeDESKey(
        RAW cryptSecretDESPassPhrase, RAW cryptSecretDESAlgorithm,
        RAW cryptSecretDESSalt, RAW cryptSecretDESIterationCount )
    {
        try {
            decryptSessionSecretDESPassPhrase( cryptSecretDESPassPhrase,
                cryptSecretDESAlgorithm, cryptSecretDESSalt,
                cryptSecretDESIterationCount );
            makeSessionSecretDESKey();
        } catch( Exception x ) {
            x.printStackTrace();
        }
    }

    /**
     * Called from Client Application
     */
    public static final String getLocRSAPubMod() {
        String rtrnString = "getLocRSAPubMod failed";
        try {
            if( null == locRSAPubMod ) makeLocRSAKeys();
            rtrnString = locRSAPubMod.toString();
        } catch( Exception x ) {
            x.printStackTrace();
        }
        return rtrnString;
    }

    /**
     * Called from Client Application
     */
    public static final String getLocRSAPubExp() {
        String rtrnString = "getLocRSAPubExp failed";
        try {
            if( null == locRSAPubMod ) makeLocRSAKeys();
            rtrnString = locRSAPubExp.toString();
        } catch( Exception x ) {}
        return rtrnString;
    }

    /*
     * Encrypt clearText String with External RSA Public key
     */
    private static final RAW getRSACryptData( String extRSAPubMod,
        String extRSAPubExp, String clearText ) throws Exception
    {
        byte[] clearBytes = clearText.getBytes();
        return getRSACryptData( extRSAPubMod, extRSAPubExp, clearBytes );
    }
    private static final RAW getRSACryptData( String extRSAPubMod,
        String extRSAPubExp, byte[] clearBytes ) throws Exception
    {
        if( ( null == extRSAPubKey ) ||
            ( !saveExtRSAPubMod.equals( extRSAPubMod ) ) )
            makeExtRSAPubKey( extRSAPubMod, extRSAPubExp );
        cipherRSA.init( Cipher.ENCRYPT_MODE, extRSAPubKey, random );
        return new RAW( cipherRSA.doFinal( clearBytes ) );
    }

    /**
     * Called as Java Stored Procedure
     * Encrypt DES Pass Phrase with External RSA Public key
     */
    public static final RAW getCryptSessionSecretDESPassPhrase(
        String extRSAPubMod, String extRSAPubExp )
    {
        RAW rtrnRAW =
            new RAW( "getCryptSessionSecretDESPassPhrase failed".getBytes() );
        try {
            if( null == sessionSecretDESPassPhraseChars )
                makeSessionSecretDESKey();
            byte[] sessionSecretDESPassPhraseBytes =
                charArrayToByteArray( sessionSecretDESPassPhraseChars );
            rtrnRAW = getRSACryptData( extRSAPubMod, extRSAPubExp,
                sessionSecretDESPassPhraseBytes );
        } catch( Exception x ) {
            java.io.CharArrayWriter errorText =
                new java.io.CharArrayWriter( 32767 );
            x.printStackTrace( new java.io.PrintWriter( errorText ) );
            rtrnRAW = new RAW( errorText.toString().getBytes() );
        }
        return rtrnRAW;
    }

    /**
     * Called as Java Stored Procedure
     * Encrypt DES Algorithm Name with External RSA Public key
     */
    public static final RAW getCryptSessionSecretDESAlgorithm(
        String extRSAPubMod, String extRSAPubExp )
    {
        RAW rtrnRAW =
            new RAW( "getCryptSessionSecretDESAlgorithm failed".getBytes() );
        try {
            if( null == sessionSecretDESPassPhraseChars ) makeSessionSecretDESKey();
            rtrnRAW = getRSACryptData( extRSAPubMod, extRSAPubExp,
                sessionSecretDESAlgorithm );
        } catch( Exception x ) {}
        return rtrnRAW;
    }

    /**
     * Called as Java Stored Procedure
     * Encrypt DES Salt with External RSA Public key
     */
    public static final RAW getCryptSessionSecretDESSalt( String extRSAPubMod,
        String extRSAPubExp )
    {
        RAW rtrnRAW = new RAW( "getCryptSessionSecretDESSalt failed".getBytes() );
        try {
            if( null == sessionSecretDESPassPhraseChars ) makeSessionSecretDESKey();
            rtrnRAW = getRSACryptData( extRSAPubMod, extRSAPubExp, salt );
        } catch( Exception x ) {}
        return rtrnRAW;
    }

    /**
     * Called as Java Stored Procedure
     * Encrypt DES Iteration Count with External RSA Public key
     */
    public static final RAW getCryptSessionSecretDESIterationCount(
        String extRSAPubMod, String extRSAPubExp )
    {
        RAW rtrnRAW =
            new RAW( "getCryptSessionSecretDESIterationCount failed".getBytes() );
        try {
            if( null == sessionSecretDESPassPhraseChars ) makeSessionSecretDESKey();
            byte[] sessionSecretDESIterationCountBytes =
                { ( byte )iterationCount };
            rtrnRAW = getRSACryptData( extRSAPubMod, extRSAPubExp,
                sessionSecretDESIterationCountBytes );
        } catch( Exception x ) {}
        return rtrnRAW;
    }

    /**
     * Called from Client Application for data updates to Server
     * Called as Java Stored Procedure
     * Encrypt data with Session Secret DES key
     */
    public static final RAW getCryptData( String clearData ) {
        if( null == clearData ) return null;
        RAW rtrnRAW = new RAW( "getCryptData failed".getBytes() );
        try {
            if( null == sessionSecretDESPassPhraseChars ) makeSessionSecretDESKey();
            cipherDES.init( Cipher.ENCRYPT_MODE, sessionSecretDESKey, paramSpec );
            rtrnRAW = new RAW( cipherDES.doFinal( clearData.getBytes() ) );
        } catch( Exception x ) {}
        return rtrnRAW;
    }

    /**
     * Called from Client Application
     */
    public static final String getDecryptData( RAW cryptData,
        RAW cryptSecretDESPassPhrase, RAW cryptSecretDESAlgorithm,
        RAW cryptSecretDESSalt, RAW cryptSecretDESIterationCount )
    {
        String rtrnString = "getDecryptData A failed";
        try {
            if( null == sessionSecretDESPassPhraseChars ) {
                makeDESKey( cryptSecretDESPassPhrase, cryptSecretDESAlgorithm,
                    cryptSecretDESSalt, cryptSecretDESIterationCount );
            }
            rtrnString = getDecryptData( cryptData );
        } catch( Exception x ) {
            x.printStackTrace();
        }
        return rtrnString;
    }

    /**
     * Called as Java Stored Procedure
     * Called from Server Application On Insert / Update
     */
    public static final String getDecryptData( RAW cryptData ) {
        if( null == cryptData ) return null;
        String rtrnString = "getDecryptData B failed";
        try {
            cipherDES.init( Cipher.DECRYPT_MODE, sessionSecretDESKey, paramSpec );
            rtrnString = new String( cipherDES.doFinal( cryptData.getBytes() ) );
        } catch( Exception x ) {
            //x.printStackTrace();
            //rtrnString = x.toString();
        }
        return rtrnString;
    }

    // Called internally on client, as needed
    private static void makeLocRSAKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance( "RSA" );
        generator.initialize( keyLengthRSA, random );
        KeyPair pair = generator.generateKeyPair();
        locRSAPrivKey = pair.getPrivate();
        locRSAPubKey = ( RSAPublicKey )pair.getPublic();
        locRSAPubMod = locRSAPubKey.getModulus();
        locRSAPubExp = locRSAPubKey.getPublicExponent();
    }

    // Called internally on Server, as needed
    private static void makeExtRSAPubKey( String extRSAPubMod,
        String extRSAPubExp ) throws Exception
    {
        BigInteger extModulus = new BigInteger( extRSAPubMod );
        BigInteger extExponent = new BigInteger( extRSAPubExp );
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec( extModulus, extExponent );
        KeyFactory kFactory = KeyFactory.getInstance( "RSA" );
        extRSAPubKey = ( RSAPublicKey )kFactory.generatePublic( keySpec );
        saveExtRSAPubMod = extRSAPubMod;
    }

    private static void makeSessionSecretDESKey() throws Exception {
        // DES Pass Phrase is generated on server and passed to client
        if( null == sessionSecretDESPassPhraseChars )
            makeSessionSecretDESPassPhrase();
        paramSpec = new PBEParameterSpec( salt, iterationCount );
        KeySpec keySpec = new PBEKeySpec( sessionSecretDESPassPhraseChars, salt,
                iterationCount );
        // Try with recommended algorithm
        sessionSecretDESKey = SecretKeyFactory.getInstance(
            sessionSecretDESAlgorithm ).generateSecret( keySpec );
        // See what algorithm used
        sessionSecretDESAlgorithm = sessionSecretDESKey.getAlgorithm();
        cipherDES = Cipher.getInstance( sessionSecretDESKey.getAlgorithm() );
    }

    private static void makeSessionSecretDESPassPhrase() {
        // Pass Phrase, Buffer size is limited by RSACipher class (on Aurora JVM)
        // Max size of data to encrypt is equal to the key bytes minus padding
        // (key.bitlength/8)-PAD_PKCS1_LENGTH (11 Bytes)
        maxPassPhraseBytes = ( keyLengthRSA / 8 ) - 11;
        sessionSecretDESPassPhraseChars = new char[maxPassPhraseBytes];
        for( int i = 0; i < maxPassPhraseBytes; i++ ) {
            // I want printable ASCII characters for PassPhrase
            sessionSecretDESPassPhraseChars[i] =
                    ( char )( random.nextInt( 126 - 32 ) + 32 );
        }
        // Appreciate the power of random
        iterationCount = random.nextInt( 10 ) + 15;
        salt = new byte[SALT_LENGTH];
        for( int i = 0; i < SALT_LENGTH; i++ ) {
            salt[i] = ( byte )random.nextInt( 256 );
        }
    }

    // Decrypt secret password key artifacts using local RSA private key
    private static void decryptSessionSecretDESPassPhrase(
        RAW cryptSecretDESPassPhrase, RAW cryptSecretDESAlgorithm,
        RAW cryptSecretDESSalt, RAW cryptSecretDESIterationCount )
        throws Exception
    {
        cipherRSA.init( Cipher.DECRYPT_MODE, locRSAPrivKey );
        byte[] cryptBytes;
        cryptBytes = cryptSecretDESPassPhrase.getBytes();
        sessionSecretDESPassPhraseChars =
            byteArrayToCharArray( cipherRSA.doFinal( cryptBytes ) );
        cryptBytes = cryptSecretDESAlgorithm.getBytes();
        sessionSecretDESAlgorithm = new String( cipherRSA.doFinal( cryptBytes ) );
        cryptBytes = cryptSecretDESSalt.getBytes();
        salt = cipherRSA.doFinal( cryptBytes );
        cryptBytes = cryptSecretDESIterationCount.getBytes();
        iterationCount = cipherRSA.doFinal( cryptBytes )[0];
    }

    // The JDK allows us to caste a byte array to and from a char array
    // That presumes a 16-bit Unicode char can be expressed in an 8-bit byte
    // However, JDeveloper complains about that practice, so we use util methods
    static char[] byteArrayToCharArray( byte[] bytes ) {
        char[] rtrnArray = new char[bytes.length];
        for ( int i = 0; i < bytes.length; i++ ) {
            rtrnArray[i] = ( char )bytes[i];
        }
        return rtrnArray;
    }

    static byte[] charArrayToByteArray( char[] chars ) {
        byte[] rtrnArray = new byte[chars.length];
        for ( int i = 0; i < chars.length; i++ ) {
            rtrnArray[i] = ( byte )chars[i];
        }
        return rtrnArray;
    }

    // As some users may have received the 2-Factor code without internal dashes
    // or with extra characters, not part of the original code. Format what they
    // type in.
    public static String checkFormat2Factor( String twoFactor ) {
        if( null == twoFactor ) return "";
        int twoFactLen = twoFactor.length();
        if( 0 == twoFactLen ) return twoFactor;
        // Otherwise, only use numeric values and insert dash after every 4 chars
        StringBuffer sB = new StringBuffer();
        int used = 0;
        char testChar;
        for( int i = 0; i < twoFactLen; i++ ) {
            testChar = twoFactor.charAt( i );
            if( Character.isDigit( testChar ) ) {
                sB.append( testChar );
                used++;
                if( sB.length() == twoFactorLength ) return sB.toString();
                // Insert dash if we have accepted a multiple of 4 chars
                if( 0 == ( used % 4 ) ) sB.append( "-" );
            }
        }
        return sB.toString();
    }

    /**
     * Main method for testing this class from the client
     * @param args
     */
    public static void main( String[] args ) {
        try {
            // This should probably be pulled out of code and put in admin app
            System.out.println( "Main encodes a new APPVER password if given." );
            System.out.println( "After encoding, paste encoded string" );
            System.out.println( location );
            if( args.length != 0 && args[0] != null ) {
                String encodeThis = args[0];
                if( ! encodeThis.equals(checkFormat2Factor(encodeThis)) ) {
                    encodeThis = "jdbc:oracle:thin:appver/" + encodeThis +
                        "@localhost:1521:orcl";
                        //"@localhost:1521:apver";
                    String encoded = OJSC.x( encodeThis );
                    System.out.println( encoded );
                    encodeThis = OJSC.y( encoded );
                    System.out.println( encodeThis );
                    System.exit(0);
                }
            } else System.out.println(
                "You may enter APPVER password on command line." );
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        System.exit( 0 );
    }
}
