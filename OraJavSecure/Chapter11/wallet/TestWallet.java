// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 11

// Use oraclepki.jar to read wallet for credential
// Use ojdbc5_g.jar to do trace
// java -cp %CLASSPATH%;C:\app\oracle\product\11.2.0\client_1\jlib\oraclepki.jar TestWallet
// java -cp .;%ORACLE_HOME%\jdbc\lib\ojdbc5_g.jar;C:\app\oracle\product\11.2.0\client_1\jlib\oraclepki.jar
//    -Doracle.jdbc.Trace=true -Djava.util.logging.config.file=trace.cfg TestWallet > temp.txt 2> temp2.txt
import java.sql.*;
import oracle.jdbc.pool.*;

import oracle.jdbc.driver.*;
import java.util.*;

public class TestWallet {
    public static void main(String args[]) throws ClassNotFoundException,
        SQLException
    {
        // Set the tns_admin to find tnsnames.ora, the connect identifier
        // Note:  Use use forward slashes as directory separators
        System.setProperty("oracle.net.tns_admin",
            //"C:/app/oracle/product/11.2.0/client_1/network/admin");
"C:/app/product/11.2.0/dbhome/NETWORK/ADMIN");
        Properties info = new Properties();
        String username = System.getProperty( "user.name" );
        info.put("oracle.net.wallet_location",
            "(SOURCE=(METHOD=file)(METHOD_DATA=(DIRECTORY=C:/Users/" +
            username + "/" + username + ")))");
        System.out.println( "Looking in: C:/Users/" + username + "/" + username );

        // These settings are only functional with
        // Oracle Advanced Security network encryption
        //info.put("oracle.net.encryption_client", "ACCEPTED");
        //info.put("oracle.net.encryption_client", "REQUIRED");
        //info.put("oracle.net.encryption_client", "REJECTED");
        info.put("oracle.net.encryption_types_client", "AES192");

        OracleDataSource ds = new OracleDataSource();

        // Must be run as an account that can SSL - OS User is also Oracle User
        // Else, Exception in thread "main" java.sql.SQLException: ORA-28150: proxy not authorized to connect as client
        // Connect as appver or appusr
        // Requires an entry in tnsnames.ora for each wallet connection
        ds.setURL("jdbc:oracle:thin:@orcl_appusr");
        //ds.setURL("jdbc:oracle:thin:@orcl_appver");

        // Compare to non-wallet connection
        //ds.setURL("jdbc:oracle:thin:@sid");
        //info.put("user", "userid");
        //info.put("password", "xxxxxxxx");

        ds.setConnectionProperties(info);
        Connection c = ds.getConnection();

        OracleConnection conn = (OracleConnection)c;

        Properties prop = new Properties();
        prop.setProperty( OracleConnection.PROXY_USER_NAME, username );
        conn.openProxySession(OracleConnection.PROXYTYPE_USER_NAME, prop);
        String metrics[] = new String[OracleConnection.END_TO_END_STATE_INDEX_MAX];
        metrics[OracleConnection.END_TO_END_CLIENTID_INDEX] = username;
        conn.setEndToEndMetrics( metrics, ( short )0 );

        Statement stmt = conn.createStatement();
        ResultSet rset;
        rset = stmt.executeQuery("SELECT USER FROM DUAL" );
        while (rset.next()) {
            System.out.println( "Oracle User = " + rset.getString(1) );
        }
        rset.close();
        stmt.close();
        conn.close();
    }
}
