// Copyright 2011, Dave Coffin

// From Chapter 8

//import com.sun.security.auth.module.NTSystem;
import java.lang.reflect.Method;

public class PlatformReflectTest {
    public static void main( String[] args ) {
        String rtrnString = null;
        //System.getProperties().list(System.out);
        System.out.println("Arch: " + System.getProperty("os.arch") +
            ", OSName: " + System.getProperty("os.name"));
        // Need try / catch around use of reflection
        try {
            if ((System.getProperty("os.arch").equals("x86") ||
                System.getProperty("os.arch").endsWith("64")) &&
                System.getProperty("os.name").startsWith("Windows") )
            {
                //NTSystem mNTS = new NTSystem();
                Class mNTS = Class.forName( "com.sun.security.auth.module.NTSystem" );

                //String domain = mNTS.getDomain().toUpperCase();
                Method classMethod = mNTS.getMethod( "getDomain" );
                String domain = ( String )classMethod.invoke( mNTS.newInstance() );
                domain = domain.toUpperCase();

                //String name = mNTS.getName().toUpperCase();
                classMethod = mNTS.getMethod( "getName" );
                String name = ( String )classMethod.invoke( mNTS.newInstance() );
                name = name.toUpperCase();

                System.out.println( "Domain: " + domain + ", Name: " + name );
                if ( ( name != null ) && ( !name.equals( "" ) ) &&
                    ( domain != null ) ) {
                    rtrnString = name;
                }
            } else {
                // Assuming Unix
                //com.sun.security.auth.module.UnixSystem mUX =
                //  new com.sun.security.auth.module.UnixSystem();
                Class mUX = Class.forName( "com.sun.security.auth.module.UnixSystem" );

                //String name = mUX.getUsername().getUsername();
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
        System.out.println( rtrnString );
    }
}