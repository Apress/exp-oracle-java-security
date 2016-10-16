// Copyright 2011, David Coffin
// Chapter8/OraSSOTests2.java
// Must have Oracle ucp.jar on client classpath

import java.sql.ResultSet;
import java.sql.Statement;

import java.util.Enumeration;
import java.util.Properties;

import oracle.jdbc.OracleConnection;

import oracle.ucp.jdbc.PoolDataSourceFactory;
import oracle.ucp.jdbc.PoolDataSource;

import orajavsec.OracleJavaSecure;


public class OraSSOTests2 {
    private String appusrConnString =
        "jdbc:oracle:thin:appusr/password@localhost:1521:orcl";
    private String appusrConnURL =
        "jdbc:oracle:oci:@(description=(address=(host=" +
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
                OraSSOTests2 ssoTest = new OraSSOTests2();
                ssoTest.doTest5();
            } else {
                System.out.println( "No OS User ID" );
            }
        } catch( Exception x ) {
            System.out.println( x.toString() );
        }
        System.exit( 0 );
    }

   void doTest5() {
        OracleConnection conn = null;
        try {
            PoolDataSource cpool = PoolDataSourceFactory.getPoolDataSource();
            cpool.setConnectionFactoryClassName("oracle.jdbc.pool.OracleDataSource");
            cpool.setURL( appusrConnString );
            /*
            cpool.setURL(appusrConnURL);
            cpool.setUser(appusrConnUser);
            cpool.setPassword(appusrConnPassword);
            // Or
            cpool.setURL("jdbc:oracle:thin:@localhost:1521:Orcl" );
            cpool.setUser(appusrConnUser);
            cpool.setPassword(appusrConnPassword);
            */
            cpool.setInitialPoolSize(5);
            cpool.setMinPoolSize(2);
            cpool.setMaxPoolSize(10);

            conn = (OracleConnection)cpool.getConnection();

            Properties prop = new Properties();
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

            // These are empty Properties - OK
            prop = cpool.getConnectionFactoryProperties();
            prop = cpool.getConnectionProperties();
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
/* Result
OraJavSecure\Chapter8>javac -classpath "%CLASSPATH%";ucp.jar OraSSOTests2.java

OraJavSecure\Chapter8>java -classpath "%CLASSPATH%";ucp.jar OraSSOTests2
Domain: ORGDOMAIN, Name: OSUSER

Is proxy session: true
user                 : OSUSER
userenv proxy_user   : APPUSR
userenv current_user : OSUSER
userenv session_user : OSUSER
userenv os_user      : OSUSER
userenv ip_address   : 127.0.0.1
userenv terminal     : unknown
userenv client_id    : OSUSER
Read HR view!!!!!!!!!!!!!!!!!!!!

OraJavSecure\Chapter8>
*/
