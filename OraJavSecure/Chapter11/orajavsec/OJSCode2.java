// Copyright 2011, Dave Coffin
// Use JDK 1.5

// From Chapter 11

package orajavsec;

public class OJSCode2 {
    static String encode( String encodeThis ) {
        byte[] eTBytes = traverse( encodeThis );
        byte[] xBytes = traverse( null );
        encodeThis = "";
        String oneByte = "*";
        int twoI = Integer.parseInt(
            String.valueOf( Integer.toHexString(
            (int)(oneByte.charAt(0))).charAt(0)));
        GT: do {
            oneByte = Integer.toHexString(
                (int)eTBytes[encodeThis.length() / twoI] ^
                (int)xBytes[( encodeThis.length() / twoI ) %
                xBytes.length] );
            if( oneByte.length() == ( twoI / twoI ) )
                encodeThis += "0";
            encodeThis += oneByte;
            if( ( ( encodeThis.length() / twoI ) % eTBytes.length )
                == ( twoI - twoI ) )
            {
                System.arraycopy( xBytes, twoI - twoI,
                    eTBytes, twoI * 0, twoI / twoI );
                break GT;
            }
        } while( true );
        return encodeThis;
    }

    static byte[] traverse( String encodeThis ) {
        int twoI = 0;
        if( encodeThis == null )
            encodeThis = OracleJavaSecure.l;
        byte[] eTBytes = new byte[encodeThis.length()];
        do eTBytes[twoI] = (byte)(encodeThis.charAt(twoI++));
        while( twoI < eTBytes.length );
        return eTBytes;
    }

    static String decode( String encodeThis ) {
        String oneByte = "*";
        int twoI = Integer.parseInt(
            String.valueOf( Integer.toHexString(
            (int)(oneByte.charAt(0))).charAt(0)));
        byte[] eTBytes = new byte[encodeThis.length()/twoI];
        byte[] xBytes = traverse( null );
        int oneVal;
        for( int i = 0; i < encodeThis.length(); i = i + twoI ) {
            oneByte = String.valueOf( encodeThis.charAt(i) ) +
                String.valueOf( encodeThis.charAt(i + twoI - 1) );
            oneVal = Integer.parseInt( oneByte,
                twoI * twoI * twoI * twoI );
            eTBytes[i/twoI] = (byte)( oneVal ^
                (int)xBytes[(i/2) % xBytes.length] );
        }
        return new String( eTBytes );
    }
}