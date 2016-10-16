//CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED appsec."orajavsec/OJSC" AS

// Copyright 2011, Dave Coffin

package orajavsec;

public class OJSC {
    static String x( String I1ll1 ) {
        byte[] lII1l = lI1ll( I1ll1 );
        byte[] ll1I1 = lI1ll( null );
        I1ll1 = "";
        String ll11I = "*";
        int IlIl1 = Integer.parseInt(
            String.valueOf( Integer.toHexString(
            (int)(ll11I.charAt(0))).charAt(0)));
        I11lI: do {
            ll11I = Integer.toHexString(
                (int)lII1l[I1ll1.length() / IlIl1] ^
                (int)ll1I1[( I1ll1.length() / IlIl1 ) %
                ll1I1.length] );
            if( ll11I.length() == ( IlIl1 / IlIl1 ) )
                I1ll1 += "0";
            I1ll1 += ll11I;
            if( ( ( I1ll1.length() / IlIl1 ) % lII1l.length )
                == ( IlIl1 - IlIl1 ) )
            {
                System.arraycopy( ll1I1, IlIl1 - IlIl1,
                    lII1l, IlIl1 * 0, IlIl1 / IlIl1 );
                break I11lI;
            }
        } while( true );
        return I1ll1;
    }

    static byte[] lI1ll( String I1ll1 ) {
        int IlIl1 = 0;
        if( I1ll1 == null )
            I1ll1 = OracleJavaSecure.l;
        byte[] lII1l = new byte[I1ll1.length()];
        do lII1l[IlIl1] = (byte)(I1ll1.charAt(IlIl1++));
        while( IlIl1 < lII1l.length );
        return lII1l;
    }

    static String y( String I1ll1 ) {
        String ll11I = "*";
        int IlIl1 = Integer.parseInt(
            String.valueOf( Integer.toHexString(
            (int)(ll11I.charAt(0))).charAt(0)));
        byte[] lII1l = new byte[I1ll1.length()/IlIl1];
        byte[] ll1I1 = lI1ll( null );
        int oneVal;
        for( int i = 0; i < I1ll1.length(); i = i + IlIl1 ) {
            ll11I = String.valueOf( I1ll1.charAt(i) ) +
                String.valueOf( I1ll1.charAt(i + IlIl1 - 1) );
            oneVal = Integer.parseInt( ll11I,
                IlIl1 * IlIl1 * IlIl1 * IlIl1 );
            lII1l[i/IlIl1] = (byte)( oneVal ^
                (int)ll1I1[(i/2) % ll1I1.length] );
        }
        return new String( lII1l );
    }
}