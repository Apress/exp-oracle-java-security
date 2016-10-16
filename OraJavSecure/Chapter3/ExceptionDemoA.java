/*
 * Chapter3/ExceptionDemoA.java
 * Copyright 2011, David Coffin
 */
import java.io.FileInputStream;
public class ExceptionDemoA {
    public static void main( String[] args ) {
        try {
            ExceptionDemoA m = new ExceptionDemoA();
            String mS = m.doWork();
            System.out.println( mS );
        } catch( Exception x ) {
            System.out.println( x.toString() );
        }
        System.exit(0);
    }
    String doWork() throws Exception {
        FileInputStream tempFileIS = new FileInputStream( "C:/Windows/win.ini" );
        tempFileIS.read();
        // ...
        if( tempFileIS != null ) tempFileIS.close();
        return "success";
    }
}
