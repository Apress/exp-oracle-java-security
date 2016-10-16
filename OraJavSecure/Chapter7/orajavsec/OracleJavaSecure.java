//CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED appsec."orajavsec/OracleJavaSecure" AS
// First
//      SET ROLE APPSEC_ROLE;

// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 7

package orajavsec;

import java.math.BigInteger;

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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import oracle.jdbc.driver.OracleDriver;

import oracle.sql.RAW;

/*
 * OracleJavaSecure class sits at both ends of the client/server conversation
 * providing encryption / decryption and other functions
 */
public class OracleJavaSecure {
    // Everything is static - one value per virtual machine (one VM per session)
    private static SecureRandom random = new SecureRandom();
    private static Cipher cipherRSA;
    static {
        try {
            cipherRSA = Cipher.getInstance( "RSA" );
        } catch( Exception x ) {}
    }
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
    private static Connection conn;
    // This default connection is used on server side (java stored procedure)
    // You may also find an occassion to write error trapping / troubleshooting
    // data from the java running in the database server
    static {
        try {
            // The following throws an exception when running on workstation
            conn = new OracleDriver().defaultConnection();
        } catch( Exception x ) {}
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
     * This is for Chapter 7 testing, then for Chapter 10
     */
    public static final void resetKeys() {
        locRSAPubMod = null;
        saveExtRSAPubMod = null;
        extRSAPubKey = null;
        sessionSecretDESPassPhraseChars = null;
        sessionSecretDESKey = null;
        sessionSecretDESAlgorithm = "PBEWithSHA1AndDESede";
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
     * Called as or from Java Stored Procedure
     * Public in Chapter 5, private thereafter
     * After Chapter 5, throws Exception rather than try / catch
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

    // Decrypt client-provided secret passphrase using external RSA public key
    // Unused
    /*
    private static char[] decryptClientDESPassPhrase( RAW cryptSecretDESPassPhrase )
        throws Exception
    {
        cipherRSA.init( Cipher.DECRYPT_MODE, extRSAPubKey );
        byte[] cryptBytes;
        cryptBytes = cryptSecretDESPassPhrase.getBytes();
        return byteArrayToCharArray( cipherRSA.doFinal( cryptBytes ) );
    }
    */

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

    /**
     * Main method for testing this class from the client
     * @param args
     */
    public static void main( String[] args ) {
        try {
        } catch ( Exception x ) {
            x.printStackTrace();
        } finally {
            try {
                if( null != conn ) conn.close();
            } catch( Exception y ) {}
        }
        System.exit( 0 );
    }
}
