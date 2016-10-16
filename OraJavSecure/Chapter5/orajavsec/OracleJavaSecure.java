//CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED appsec."orajavsec/OracleJavaSecure" AS
// First
//      SET ROLE APPSEC_ROLE;

// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 5

package orajavsec;

import java.math.BigInteger;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.RSAPublicKeySpec;

import java.sql.Connection;
import java.sql.DriverManager;

import java.util.Date;

import javax.crypto.Cipher;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleTypes;

import oracle.jdbc.driver.OracleDriver;

import oracle.sql.RAW;

/*
 * OracleJavaSecure class sits at both ends of the client/server conversation
 * providing encryption / decryption and other functions
 */
public class OracleJavaSecure {
    private static boolean testingOnServer = false;
    private static String appsecConnString =
        "jdbc:oracle:thin:AppSec/password@localhost:1521:Orcl";

    // Everything is static - one value per virtual machine (one VM per session)
    private static SecureRandom random;
    private static Cipher cipherRSA;
    private static int keyLengthRSA = 1024;
    private static Key locRSAPrivKey;
    private static RSAPublicKey locRSAPubKey;
    private static BigInteger locRSAPubMod = null;
    private static BigInteger locRSAPubExp;
    private static String saveExtRSAPubMod = null;
    private static RSAPublicKey extRSAPubKey = null;
    // On the client, this connection is for a session and is not normally closed
    // For use with Oracle servers that limit connection time, may need to test
    // and renew this connection periodically
    // On the Oracle server, you should never close() the default connection
    // it never needs to be renewed
    private static Connection conn;
    // This default connection is used on server side (java stored procedure)
    // You may also find an occassion to write error trapping / troubleshooting
    // data from the java running in the database server
    static {
        try {
            //conn = DriverManager.getConnection("jdbc:default:connection");
            conn = new OracleDriver().defaultConnection();
        } catch ( Exception x ) {
        }
    }

    /**
     * Called from Client Application set the Connection for use with this class
     */
    public static final void setConnection( Connection c ) {
        conn = c;
    }

    // A private constructor keeps everyone from instantiating this class
    // All methods and members are static
    private OracleJavaSecure() {
    }

    /**
     * Called from Client Application
     */
    public static final String getLocRSAPubMod() {
        String rtrnString = "getLocRSAPubMod failed";
        try {
            if ( null == locRSAPubMod ) makeLocRSAKeys();
            rtrnString = locRSAPubMod.toString();
        } catch ( Exception x ) {
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
            if ( null == locRSAPubMod ) makeLocRSAKeys();
            rtrnString = locRSAPubExp.toString();
        } catch ( Exception x ) {}
        return rtrnString;
    }

    /**
     * Called as or from Java Stored Procedure
     * Public in Chapter 5, private thereafter
     * After Chapter 5, throws Exception rather than try / catch
     * Encrypt clearText String with External RSA Public key
     */
    public static final RAW getRSACryptData( String extRSAPubMod,
        String extRSAPubExp, String clearText )
    {
        RAW rtrnRaw =
            new RAW( "getRSACryptData failed".getBytes() );
        try {
            if ( ( null == extRSAPubKey ) ||
                ( !saveExtRSAPubMod.equals( extRSAPubMod ) ) )
                makeExtRSAPubKey( extRSAPubMod, extRSAPubExp );
            cipherRSA.init( Cipher.ENCRYPT_MODE, extRSAPubKey, random );
            rtrnRaw = new RAW( cipherRSA.doFinal( clearText.getBytes() ) );
        } catch ( Exception x ) {}
        return rtrnRaw;
    }

    /**
     * Called from Client Application - Chapter 5 testing only
     * Decrypt cryptData RAW with Local RSA Private key
     */
    public static final String getRSADecryptData( RAW cryptData ) {
        String rtrnString = "getRSADecryptData failed";
        try {
            cipherRSA.init( Cipher.DECRYPT_MODE, locRSAPrivKey );
            rtrnString = new String( cipherRSA.doFinal( cryptData.getBytes() ) );
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        return rtrnString;
    }

    // Called internally on client, as needed
    private static void makeLocRSAKeys() throws Exception {
        makeCryptUtilities();
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
        makeCryptUtilities();
        BigInteger extModulus = new BigInteger( extRSAPubMod );
        BigInteger extExponent = new BigInteger( extRSAPubExp );
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec( extModulus, extExponent );
        KeyFactory kFactory = KeyFactory.getInstance( "RSA" );
        extRSAPubKey = ( RSAPublicKey )kFactory.generatePublic( keySpec );
        saveExtRSAPubMod = extRSAPubMod;
    }

    // Called internally on client and server
    private static void makeCryptUtilities() throws Exception {
        random = new SecureRandom();
        cipherRSA = Cipher.getInstance( "RSA" );
    }

    /**
     * Main method for testing this class from the client
     * @param args
     */
    public static void main( String[] args ) {
        try {
            // As a client application
            String clientPubModulus = getLocRSAPubMod();
            String clientPubExponent = getLocRSAPubExp();
            // Send modulus and exponent to Oracle Server, then
            // As if I were the Oracle server
            makeExtRSAPubKey( clientPubModulus, clientPubExponent );
            cipherRSA.init( Cipher.ENCRYPT_MODE, extRSAPubKey, random );
            Date clientDate = new Date();
            String sampleData = clientDate.toString();
            byte[] clearBytes = sampleData.getBytes();
            byte[] cryptBytes = cipherRSA.doFinal( clearBytes );
            // Send the cryptBytes back to the client application, then
            // As a client application
            cipherRSA.init( Cipher.DECRYPT_MODE, locRSAPrivKey );
            byte[] newClearBytes = cipherRSA.doFinal( cryptBytes );
            String newSampleData = new String( newClearBytes );
            System.out.println( "Client date: " + newSampleData );

            if( testingOnServer ) {
                // Since not on the Server, must load Oracle-specific Driver
                Class.forName( "oracle.jdbc.driver.OracleDriver" );
                // This will set the static member "conn" to a new Connection
                conn = DriverManager.getConnection( appsecConnString );
                OracleCallableStatement stmt =
                    ( OracleCallableStatement )conn.prepareCall(
                    "CALL p_get_rsa_crypt_sysdate(?,?,?,?,?)" );
                stmt.registerOutParameter( 3, OracleTypes.RAW );
                stmt.registerOutParameter( 4, OracleTypes.NUMBER );
                stmt.registerOutParameter( 5, OracleTypes.VARCHAR );
                stmt.setString( 1, clientPubModulus );
                stmt.setString( 2, clientPubExponent );
                stmt.setNull(   3, OracleTypes.RAW );
                stmt.setInt(    4, 0 );
                stmt.setNull(   5, OracleTypes.VARCHAR );
                stmt.executeUpdate();

                int errNo = stmt.getInt( 4 );
                if( errNo != 0 ) {
                    String errMsg = stmt.getString( 5 );
                    System.out.println( "Oracle error " + errNo + ", " + errMsg );
                    System.out.println( (stmt.getRAW( 3 )).toString() );
                } else {
                    RAW cryptData = stmt.getRAW( 3 );
                    newSampleData = getRSADecryptData( cryptData );
                    System.out.println( "Server date: " + newSampleData );
                }
            }
        } catch ( Exception x ) {
            x.printStackTrace();
        }
        System.exit( 0 );
    }
}
