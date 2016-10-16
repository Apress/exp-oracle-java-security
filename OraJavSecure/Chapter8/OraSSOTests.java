// Copyright 2011, David Coffin
// Chapter8/OraSSOTests.java


import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import java.util.Enumeration;
import java.util.Properties;

import oracle.jdbc.OracleConnection;

import oracle.jdbc.pool.OracleDataSource;
import oracle.jdbc.pool.OracleOCIConnectionPool;

import orajavsec.OracleJavaSecure;


public class OraSSOTests {
    private String appusrConnString =
        "jdbc:oracle:thin:appusr/password@localhost:1521:orcl";
    private String appusrConnOCIURL =
        "jdbc:oracle:oci:@(description=(address=(host=" +
        "127.0.0.1)(protocol=tcp)(port=1521))(connect_data=" +
        "(INSTANCE_NAME=orcl)(SERVICE_NAME=orcl)))";
        // Or
        //"(INSTANCE_NAME=orcl)(SERVICE_NAME=orcl.org.com)))";
    private String appusrConnThinURL =
        "jdbc:oracle:thin:@(description=(address=(host=" +
        "127.0.0.1)(protocol=tcp)(port=1521))(connect_data=" +
        "(INSTANCE_NAME=orcl)(SERVICE_NAME=orcl)))";
        // Or
        //"(INSTANCE_NAME=orcl)(SERVICE_NAME=orcl.org.com)))";
    private String appusrConnUser = "appusr";
    private String appusrConnPassword = "password";

    static String userName = "";
    public static void main( String[] args ) {
        try {
            userName = OracleJavaSecure.getOSUserID();
            if ( ( userName != null ) && ( !userName.equals( "" ) ) ) {
                Class.forName( "oracle.jdbc.driver.OracleDriver" );
                OraSSOTests ssoTest = new OraSSOTests();
                ssoTest.doTest1();
                ssoTest.doTest2();
                ssoTest.doTest3();
                ssoTest.doTest4();
            } else {
                System.out.println( "No OS User ID" );
            }
        } catch( Exception x ) {
            System.out.println( x.toString() );
        }
        System.exit( 0 );
    }

    void doTest1() {
        OracleConnection conn = null;
        try {
            conn = (OracleConnection) DriverManager.getConnection( appusrConnString );

            String metrics[] =
                new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
            metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = userName;
            conn.setEndToEndMetrics( metrics, ( short )0 );
            //String[] newMetrics = conn.getEndToEndMetrics();
            //for ( int i = 0; i < newMetrics.length; i++ )
            //    System.out.println( newMetrics[i] );

            // Note OSUser can be spoofed by local user account
            // My NTSystem user can also be spoofed by local domain
            // So check for correct domain and use Network Access Control (NAC)
            // to assure account is part of the managed domain
            Statement stmt = conn.createStatement();
            System.out.println( "\nIs proxy session: " + conn.isProxySession() );
            ResultSet rs = stmt.executeQuery(
                "SELECT USER " +
                ", SYS_CONTEXT('USERENV','PROXY_USER') " +
                ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                ", SYS_CONTEXT('USERENV','OS_USER') " +
                ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                ", SYS_CONTEXT('USERENV','TERMINAL') " +
                ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                " FROM DUAL" );
            if ( rs.next() ) {
                System.out.println( "user                 : " +
                        rs.getString( 1 ) );
                System.out.println( "userenv proxy_user   : " +
                        rs.getString( 2 ) );
                System.out.println( "userenv current_user : " +
                        rs.getString( 3 ) );
                System.out.println( "userenv session_user : " +
                        rs.getString( 4 ) );
                System.out.println( "userenv os_user      : " +
                        rs.getString( 5 ) );
                System.out.println( "userenv ip_address   : " +
                        rs.getString( 6 ) );
                System.out.println( "userenv terminal     : " +
                        rs.getString( 7 ) );
                System.out.println( "userenv client_id    : " +
                        rs.getString( 8 ) );
            }

            try {
                stmt.execute("CALL appsec.p_check_hrview_access()");
                stmt.execute("ALTER SESSION SET CURRENT_SCHEMA=hr");
                rs = stmt.executeQuery( "SELECT COUNT(*) FROM v_employees_public" );
                System.out.println( "Read HR view!!!!!!!!!!!!!!!!!!!!" );
            } catch( Exception y ) {
                System.out.println( "Cannot read HR view." );
            }

            conn.close( OracleConnection.PROXY_SESSION );

        } catch ( Exception x ) {
            x.printStackTrace();
        }
    }


    void doTest2() {
        OracleConnection conn = null;
        try {
            conn = (OracleConnection) DriverManager.getConnection( appusrConnString  );

            Properties prop = new Properties();
            prop.setProperty( OracleConnection.PROXY_USER_NAME, userName );
            conn.openProxySession(OracleConnection.PROXYTYPE_USER_NAME, prop);

            String metrics[] =
                new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
            metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = userName;
            conn.setEndToEndMetrics( metrics, ( short )0 );

            Statement stmt = conn.createStatement();
            System.out.println( "\nIs proxy session: " + conn.isProxySession() );
            ResultSet rs = stmt.executeQuery(
                "SELECT USER " +
                ", SYS_CONTEXT('USERENV','PROXY_USER') " +
                ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                ", SYS_CONTEXT('USERENV','OS_USER') " +
                ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                ", SYS_CONTEXT('USERENV','TERMINAL') " +
                ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                " FROM DUAL" );
            if ( rs.next() ) {
                System.out.println( "user                 : " +
                        rs.getString( 1 ) );
                System.out.println( "userenv proxy_user   : " +
                        rs.getString( 2 ) );
                System.out.println( "userenv current_user : " +
                        rs.getString( 3 ) );
                System.out.println( "userenv session_user : " +
                        rs.getString( 4 ) );
                System.out.println( "userenv os_user      : " +
                        rs.getString( 5 ) );
                System.out.println( "userenv ip_address   : " +
                        rs.getString( 6 ) );
                System.out.println( "userenv terminal     : " +
                        rs.getString( 7 ) );
                System.out.println( "userenv client_id    : " +
                        rs.getString( 8 ) );
            }

            try {
                stmt.execute("CALL appsec.p_check_hrview_access()");
                stmt.execute("ALTER SESSION SET CURRENT_SCHEMA=hr");
                rs = stmt.executeQuery( "SELECT COUNT(*) FROM v_employees_public" );
                System.out.println( "Read HR view!!!!!!!!!!!!!!!!!!!!" );
            } catch( Exception y ) {
                System.out.println( "Cannot read HR view." );
            }

            conn.close( OracleConnection.PROXY_SESSION );

        } catch ( Exception x ) {
            x.printStackTrace();
        }
    }


    void doTest3() {
        OracleConnection conn = null;
        try {
            OracleOCIConnectionPool cpool = new OracleOCIConnectionPool();
            cpool.setURL(appusrConnOCIURL);
            cpool.setUser(appusrConnUser);
            cpool.setPassword(appusrConnPassword);

            Properties prop = new Properties();
            prop.put (OracleOCIConnectionPool.CONNPOOL_MIN_LIMIT, "2");
            prop.put (OracleOCIConnectionPool.CONNPOOL_MAX_LIMIT, "10");
            prop.put (OracleOCIConnectionPool.CONNPOOL_INCREMENT, "1");
            cpool.setPoolConfig(prop);

            prop.setProperty(OracleOCIConnectionPool.PROXY_USER_NAME, userName );
            conn = (OracleConnection)cpool.getProxyConnection(
                OracleOCIConnectionPool.PROXYTYPE_USER_NAME, prop);

            // Both of these methods work for OCI pool proxy connections
            //conn.setClientIdentifier( userName );
            String metrics[] = new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
            metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = userName;
            conn.setEndToEndMetrics( metrics, ( short )0 );

            //prop = new Properties();
            //prop.setProperty(OracleConnection.PROXY_USER_NAME, userName );
            //conn.openProxySession(OracleConnection.PROXYTYPE_USER_NAME, prop);

            Statement stmt = conn.createStatement();
            System.out.println( "\nIs proxy session: " + conn.isProxySession() );
            ResultSet rs = stmt.executeQuery(
                "SELECT USER " +
                ", SYS_CONTEXT('USERENV','PROXY_USER') " +
                ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                ", SYS_CONTEXT('USERENV','OS_USER') " +
                ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                ", SYS_CONTEXT('USERENV','TERMINAL') " +
                ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                " FROM DUAL" );
            if ( rs.next() ) {
                System.out.println( "user                 : " +
                        rs.getString( 1 ) );
                System.out.println( "userenv proxy_user   : " +
                        rs.getString( 2 ) );
                System.out.println( "userenv current_user : " +
                        rs.getString( 3 ) );
                System.out.println( "userenv session_user : " +
                        rs.getString( 4 ) );
                System.out.println( "userenv os_user      : " +
                        rs.getString( 5 ) );
                System.out.println( "userenv ip_address   : " +
                        rs.getString( 6 ) );
                System.out.println( "userenv terminal     : " +
                        rs.getString( 7 ) );
                System.out.println( "userenv client_id    : " +
                        rs.getString( 8 ) );
            }

            try {
                stmt.execute("CALL appsec.p_check_hrview_access()");
                stmt.execute("ALTER SESSION SET CURRENT_SCHEMA=hr");
                rs = stmt.executeQuery( "SELECT COUNT(*) FROM v_employees_public" );
                System.out.println( "Read HR view!!!!!!!!!!!!!!!!!!!!" );
            } catch( Exception y ) {
                System.out.println( "Cannot read HR view." );
            }

            conn.close( OracleConnection.PROXY_SESSION );

            prop = cpool.getPoolConfig();
            Enumeration enumer = prop.propertyNames();
            String key;
            while( enumer.hasMoreElements() ) {
                key = (String)enumer.nextElement();
                System.out.println( key + ", " + prop.getProperty( key ) );
            }

        } catch ( Exception x ) {
            x.printStackTrace();
        }
    }


    // Note that setConnectionCachingEnabled and setConnectionCacheProperties
    // are deprecated; suppress warnings with the following annotation
    //@SuppressWarnings("deprecation")
    void doTest4() {
        OracleConnection conn = null;
        try {
            OracleDataSource cpool = new OracleDataSource();
            cpool.setURL(appusrConnThinURL);
            cpool.setUser(appusrConnUser);
            cpool.setPassword(appusrConnPassword);

            // Enable Connection Caching
            cpool.setConnectionCachingEnabled(true);
            cpool.setConnectionCacheName("APP_CACHE");

            Properties prop = new Properties();
            prop.setProperty("InitialLimit", "3");
            prop.setProperty("MinLimit", "2");
            prop.setProperty("MaxLimit", "10");
            cpool.setConnectionCacheProperties(prop);

            // Enable Statement Caching
            cpool.setImplicitCachingEnabled(true);

            conn = (OracleConnection)cpool.getConnection();
            prop.setProperty(OracleConnection.PROXY_USER_NAME, userName );
            conn.openProxySession(OracleConnection.PROXYTYPE_USER_NAME, prop);

            String metrics[] =
                new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
            metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = userName;
            conn.setEndToEndMetrics( metrics, ( short )0 );

            Statement stmt = conn.createStatement();
            System.out.println( "\nIs proxy session: " + conn.isProxySession() );
            ResultSet rs = stmt.executeQuery(
                "SELECT USER " +
                ", SYS_CONTEXT('USERENV','PROXY_USER') " +
                ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                ", SYS_CONTEXT('USERENV','OS_USER') " +
                ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                ", SYS_CONTEXT('USERENV','TERMINAL') " +
                ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                " FROM DUAL" );
            if ( rs.next() ) {
                System.out.println( "user                 : " +
                        rs.getString( 1 ) );
                System.out.println( "userenv proxy_user   : " +
                        rs.getString( 2 ) );
                System.out.println( "userenv current_user : " +
                        rs.getString( 3 ) );
                System.out.println( "userenv session_user : " +
                        rs.getString( 4 ) );
                System.out.println( "userenv os_user      : " +
                        rs.getString( 5 ) );
                System.out.println( "userenv ip_address   : " +
                        rs.getString( 6 ) );
                System.out.println( "userenv terminal     : " +
                        rs.getString( 7 ) );
                System.out.println( "userenv client_id    : " +
                        rs.getString( 8 ) );
            }

            try {
                stmt.execute("CALL appsec.p_check_hrview_access()");
                stmt.execute("ALTER SESSION SET CURRENT_SCHEMA=hr");
                rs = stmt.executeQuery( "SELECT COUNT(*) FROM v_employees_public" );
                System.out.println( "Read HR view!!!!!!!!!!!!!!!!!!!!" );
            } catch( Exception y ) {
                System.out.println( "Cannot read HR view." );
            }

            conn.close( OracleConnection.PROXY_SESSION );

            prop = cpool.getConnectionCacheProperties();
            Enumeration enumer = prop.propertyNames();
            String key;
            while( enumer.hasMoreElements() ) {
                key = (String)enumer.nextElement();
                System.out.println( key + ", " + prop.getProperty( key ) );
            }

        } catch ( Exception x ) {
            x.printStackTrace();
        }
    }
}
