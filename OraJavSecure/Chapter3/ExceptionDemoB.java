/*
 * Chapter3/ExceptionDemoB.java
 * Copyright 2011, David Coffin
 */
import java.io.FileInputStream;
public class ExceptionDemoB {
    public static void main( String[] args ) {
        ExceptionDemoB m = new ExceptionDemoB();
        System.out.println( m.doWork() );
        System.exit(0);
    }
    String doWork() {
        String returnString = "attempt";
        FileInputStream tempFileIS = null;
        try {
            tempFileIS = new FileInputStream( "C:/Windows/win.ini" );
            tempFileIS.open();
            // ...
            returnString = "success";
        } catch( Exception x ) {
            System.out.println( x.toString() );
        } finally {
            try {
                if( tempFileIS != null ) tempFileIS.close();
            } catch( Exception y ){}
        }
        return returnString;
    }
}
