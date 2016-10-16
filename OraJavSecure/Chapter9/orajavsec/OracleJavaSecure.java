//CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED appsec."orajavsec/OracleJavaSecure" AS
// First
//      SET ROLE APPSEC_ROLE;
// Also having ampersands in the code without substitution variables
//      SET DEFINE OFF;

// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 9

package orajavsec;

import java.lang.reflect.Method;

import java.math.BigInteger;

import java.net.URL;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import oracle.jdbc.OracleConnection;
import oracle.jdbc.driver.OracleDriver;

import oracle.sql.RAW;

/*
 * OracleJavaSecure class sits at both ends of the client/server conversation
 * providing encryption / decryption and other functions
 */
public class OracleJavaSecure {
    // isTesting allows us to cache new 2-Factor Auth Code, even when
    // distribution is not available
    private static boolean isTesting = true;

    private static String expectedDomain = "ORGDOMAIN";
    private static String comDomain = "org.com";
    private static String smtpHost = "smtp." + comDomain;
    private static String baseURL =
        "http://www.org.com/servlet/textpage.PageServlet?ACTION=2&PAGERID=";
    private static String msgURL = "&MESSAGE=";

    private static final int USE_PAGER = 1;
    private static final int USE_SMS = 2;
    private static final int USE_EMAIL = 4;

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


    /**
     * Create 2-Factor Auth Code and Distribute to available channels
     * Return code indicating which channels used
     * This is called as a Java Stored procedure on the Oracle server
     */
    public static final String distribute2Factor( String osUser ) throws Exception {
        // Do not resend this two-factor authentication code,
        //  nor a new one using this session
        if ( twoFactorAuthChars != null ) return "0";
        int distribCode = 0;
        Statement stmt = null;
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
            String twoFactorAuth = new String( twoFactorAuthChars );
            //System.out.println(twoFactorAuth);

            // Everything you need to know about exchanging Dates (to seconds)
            // between oracle and java is encapsulated in these 3 lines
            String oraFmtSt = "YYYY-MM-DD HH24:MI:SS"; // use with to_char()
            String javaFmtSt = "yyyy-MM-d H:m:s";
            SimpleDateFormat ora2JavaDtFmt = new SimpleDateFormat( javaFmtSt );
            // Then all Dates used in Java are of type java.util.Date

            stmt = conn.createStatement();


            ResultSet rs = stmt.executeQuery(
"SELECT m.employee_id, m.com_pager_no, m.sms_phone_no, s.sms_carrier_url, e.email, " +
"SYS_CONTEXT( 'USERENV', 'IP_ADDRESS' ), " +
"TO_CHAR( c.cache_ts, '" + oraFmtSt + "' ), c.ip_address " +
"FROM hr.v_emp_mobile_nos m, hr.v_employees_public e, hr.v_sms_carrier_host s, " +
"v_two_fact_cd_cache c WHERE m.user_id = '" + osUser + "' " +
"AND e.employee_id =  m.employee_id " +
"AND s.sms_carrier_cd (+)= m.sms_carrier_cd " +
"AND c.employee_id (+)= m.employee_id " );
            if ( rs.next() ) {
                String empID     = rs.getString( 1 );
                String pagerNo   = rs.getString( 2 );
                String smsNo     = rs.getString( 3 );
                String smsURL    = rs.getString( 4 );
                String eMail     = rs.getString( 5 );
                String ipAddress = rs.getString( 6 );

                try{
                    String cTimeStamp = rs.getString( 7 );
                    String cIPAddr    = rs.getString( 8 );
                    // Ten minutes ago Date
                    Date tmaDate = new Date( (new Date()).getTime() - 10*60*1000 );
                    Date cacheDate = ora2JavaDtFmt.parse( cTimeStamp );
                    // If user coming from same IP Address within 10 minutes
                    // do not distribute Code (will overwrite code from new IP Addr)
                    if( ipAddress.equals( cIPAddr ) && cacheDate.after( tmaDate ) )
                        return "0";
                } catch( Exception z ) {}

                // Do distributions
                if( ( smsNo != null ) && ( !smsNo.equals( "" ) ) &&
                    ( smsURL != null ) && ( !smsURL.equals( "" ) )
                )
                    distribCode += distribToSMS( twoFactorAuth, smsNo, smsURL );
                if( ( pagerNo != null ) && ( !pagerNo.equals( "" ) ) )
                    distribCode += distribToPagerURL( twoFactorAuth, pagerNo );
                // Recommend not send to e-mail unless no other distrib option succeeds
                // !Uncomment code in next line!
                if( //( distribCode == 0 ) &&
                    ( eMail != null ) && ( !eMail.equals( "" ) )
                )
                    distribCode += distribToEMail( twoFactorAuth, eMail );

                if( distribCode > 0 || isTesting ) {
                    int cnt = stmt.executeUpdate(
"UPDATE v_two_fact_cd_cache SET two_factor_cd = '" + twoFactorAuth +
"', ip_address = '" + ipAddress + "', distrib_cd = " +
String.valueOf( distribCode ) + ", cache_ts=SYSDATE " +
"WHERE employee_id = " + empID );
                    if( cnt < 1 )
                        stmt.executeUpdate(
"INSERT INTO v_two_fact_cd_cache( employee_id ,two_factor_cd, distrib_cd ) VALUES " +
"( " + empID + ", '" + twoFactorAuth +"', " + String.valueOf( distribCode ) + " )" );
                }
            } else {
                stmt.executeUpdate( "CALL app_sec_pkg.p_log_error( 0, " +
                    "'user not found in distribute2Factor', '')" );
            }
        } catch( Exception x ) {
            java.io.CharArrayWriter errorText = new java.io.CharArrayWriter( 4000 );
            x.printStackTrace( new java.io.PrintWriter( errorText ) );
            stmt.executeUpdate( "CALL app_sec_pkg.p_log_error( 0, '" +
                errorText.toString() + "', '')" );
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return String.valueOf( distribCode );
    }

    /**
     * Try Distribute 2-Factor Auth Code to SMS Phone
     */
    private static final int distribToSMS( String twoFactorAuth, String smsNo,
        String smsURL )
    {
        int distribCode = 0;
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.executeUpdate( "ALTER SESSION SET SMTP_OUT_SERVER = '" +
                smtpHost + "'" );
            stmt.executeUpdate( "CALL UTL_MAIL.SEND( 'response@" +
                comDomain + "', '" + smsNo + "@" + smsURL +
                "', '', '', 'Response','" + twoFactorAuth + "' )" );
            distribCode += USE_SMS;
        } catch ( Exception x ) {
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
    private static final int distribToPagerURL( String twoFactorAuth,
        String pagerNo )
    {
        int distribCode = 0;
        try {
            URL u = new URL( baseURL + pagerNo + msgURL + twoFactorAuth );
            u.getContent();
            distribCode += USE_PAGER;
        } catch ( Exception x ) {
            System.out.println( x.toString() );
        }
        return distribCode;
    }

    /**
     * Try Distribute 2-Factor Auth Code to E-Mail
     */
    private static final int distribToEMail( String twoFactorAuth, String eMail ) {
        int distribCode = 0;
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.executeUpdate( "ALTER SESSION SET SMTP_OUT_SERVER = '" +
                smtpHost + "'" );
            stmt.executeUpdate( "CALL UTL_MAIL.SEND( 'response@" +
                comDomain + "', '" + eMail + "@" + comDomain +
                "', '', '', 'Response','" + twoFactorAuth +
                "' )" );
            distribCode += USE_EMAIL;
        } catch ( Exception x ) {
        } finally {
            try {
                if( stmt != null ) stmt.close();
            } catch( Exception y ) {}
        }
        return distribCode;
    }


    /**
     * Called from Client Application set the Connection for use with this class
     * From here on out, use OracleConnection class instead of Connection class
     */
    public static final OracleConnection setConnection( Connection c ) {
        return setConnection( (OracleConnection)c );
    }
    public static final OracleConnection setConnection( OracleConnection c ) {
        conn = null;
        // We are going to require that only we will set up proxy connections
        if( c == null || c.isProxySession() ) return null;
        else try {
            // Set up a non-pooled proxy connection with Client Identifier
            // To use an alternate solution, refer to code in Chapter8/OraSSOTests.java
            String userName = getOSUserID();
            if ( ( userName != null ) && ( !userName.equals( "" ) ) ) {
                Properties prop = new Properties();
                prop.setProperty( OracleConnection.PROXY_USER_NAME, userName );
                c.openProxySession(OracleConnection.PROXYTYPE_USER_NAME, prop);

                String metrics[] =
                    new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
                metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = userName;
                c.setEndToEndMetrics( metrics, ( short )0 );

                // If we dont get here, no Connection will be available
                conn = c;
            } else {
                // This is not a valid user
            }
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        return conn;
    }
    public static final OracleConnection setConnection( String URL ) {
        Connection c = null;
        try {
            Class.forName( "oracle.jdbc.driver.OracleDriver" );
            c = DriverManager.getConnection( URL );
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        return setConnection( c );
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
                
                System.out.println( "Domain: " + domain + ", Name: " + name );
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
            if( null == sessionSecretDESKey ) makeSessionSecretDESKey();
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
            if( null == sessionSecretDESKey ) makeSessionSecretDESKey();
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
            if( null == sessionSecretDESKey ) makeSessionSecretDESKey();
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
            if( null == sessionSecretDESKey ) makeSessionSecretDESKey();
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
            if( null == sessionSecretDESKey ) makeSessionSecretDESKey();
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
            if( null == sessionSecretDESKey ) {
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
    // type in, if length is questionable.
    public static String checkFormat2Factor( String twoFactor ) {
        String rtrnString = "";
        if( null == twoFactor ) return rtrnString;
        // Use only numeric values and insert dash after every 4 chars
        StringBuffer sB = new StringBuffer();
        int used = 0;
        char testChar;
        int twoFactLen = twoFactor.length();
        for( int i = 0; i < twoFactLen; i++ ) {
            testChar = twoFactor.charAt( i );
            if( Character.isDigit( testChar ) ) {
                sB.append( testChar );
                if( sB.length() == twoFactorLength ) {
                    rtrnString = sB.toString();
                    break;
                }
                // Insert dash if we have accepted a multiple of 4 chars
                used++;
                if( 0 == ( used % 4 ) ) sB.append( "-" );
            }
        }
        return rtrnString;
    }

    /**
     * Main method for testing this class from the client
     * @param args
     */
    public static void main( String[] args ) {
        try {
            // Test on Java client
            distribToPagerURL( "Here", "12345" );
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        System.exit( 0 );
    }
}
