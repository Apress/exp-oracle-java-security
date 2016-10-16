//CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED APPSEC."orajavsec/OJSC" AS
// First
//      SET ROLE APPSEC_ROLE;
// Notice we are creating this in schema APPSEC

// This functionality is not needed on Oracle, but load it there
// in order to compile OracleJavaSecure

// Copyright 2011, Dave Coffin
// Use JDK 1.5

// From Chapter 11

package orajavsec;

//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;
// warning: sun.misc.BASE64Encoder is Sun proprietary API
// and may be removed in a future release

/*
 * OJSCode provides simple coding for client password
 * Distribute this code in obfuscated form only
 */
public class OJSCode {
    // Notice default access - inaccessible outside of package
    static String encode( String encodeThis ) {
        // Common code
        String location = OracleJavaSecure.location;
        byte[] eTBytes = encodeThis.getBytes();
        int eTLength = eTBytes.length;
        while( eTLength > location.length() ) location += location;
        String xString = location.substring( 0, eTLength );
        byte[] xBytes = xString.getBytes();
        /* Either this
        byte[] code = new byte[eTLength];
        for( int i = 0; i < eTLength ; i++ ) {
            code[i] = (byte)( (int)eTBytes[i] ^ (int)xBytes[i] );
        }
        String decodeThis = (new BASE64Encoder()).encode( code );
        /**/
        /* Or this - creates a longer encoded String */
        StringBuffer sBuf = new StringBuffer();
        String oneByte;
        for( int i = 0; i < eTLength ; i++ ) {
            oneByte = Integer.toHexString( (int)eTBytes[i] ^ (int)xBytes[i] );
            if( oneByte.length() == 1 ) sBuf.append( "0" + oneByte );
            else sBuf.append( oneByte );
        }
        String decodeThis = sBuf.toString();
        /**/
        return decodeThis;
    }

    // BASE64Decoder.decodeBuffer() Can throw IOException
    static String decode( String decodeThis ) throws Exception {
        /* Either this
        byte[] dTBytes = (new BASE64Decoder()).decodeBuffer( decodeThis );
        int dTLength = dTBytes.length;
        /**/
        /* Or this - from the longer encoded String */
        int origLength = decodeThis.length();
        int dTLength = origLength/2;
        byte[] dTBytes = new byte[dTLength];
        String oneByte;
        int oneVal;
        int d = 0;
        for( int i = 0; i < origLength; i = i + 2 ) {
            oneByte = String.valueOf( decodeThis.charAt(i) ) +
                String.valueOf( decodeThis.charAt(i+1) );
            oneVal = Integer.parseInt( oneByte, 16 );
            dTBytes[d] = (byte)oneVal;
            d++;
        }
        /**/
        // Common code
        String location = OracleJavaSecure.location;
        while( dTLength > location.length() ) location += location;
        String xString = location.substring( 0, dTLength );
        byte[] xBytes = xString.getBytes();
        byte[] clear = new byte[dTLength];
        for( int i = 0; i < dTLength ; i++ ) {
            clear[i] = (byte)( (int)dTBytes[i] ^ (int)xBytes[i] );
        }
        return new String( clear );
    }

    public static void main( String[] args ) {
        try {
            String encoded = OJSCode.encode( "I can't do that, Dave." );
            System.out.println( encoded );
            String decoded = OJSCode.decode( encoded );
            System.out.println( decoded );
        } catch( Exception x ) {
            System.out.println( x.toString() );
        }
    }
}