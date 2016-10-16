// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12, modified for Single, conn to orcl
// Modify call to getAAConnRole() with correct Oracle instance name

package orajavsec;

import java.awt.Color;
import java.awt.Dimension;

import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import java.io.BufferedReader;

import java.io.InputStreamReader;

import java.sql.ResultSet;
import java.sql.Statement;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

import oracle.jdbc.OracleConnection;

public class PickAppManage extends JFrame {
    JFrame thisComponent = this;
    static JFrame parent;
    static OracleConnection conn;
    static String applicationID;

    private JPanel functionPanel = new JPanel();
    private JButton manageAppButton = new JButton();
    private JButton closeButton = new JButton();
    private JLabel jLabel1 = new JLabel();
    private JComboBox appClassComboBox = new JComboBox();
    private JLabel jLabel9 = new JLabel();
    private JLabel connSuccessLabel = new JLabel();
    private JLabel jLabel2 = new JLabel();

    public PickAppManage(JFrame parent) {
        this();
        this.parent = parent;
        // Post jbInit visual setup
        Login.center(this);
        parent.setVisible(false);
        this.setVisible(true);
        if (null == conn) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Your account is not permitted to use this functional screen!");
            parent.setVisible(true);
            this.setVisible(false);
        }
    }

    public PickAppManage() {
        try {
            jbInit();
            //conn = OracleJavaSecure.getAAConnRole("apver", "avadmin");
            conn = OracleJavaSecure.getAAConnRole("orcl", "avadmin");
            dataInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(705, 245));
        this.setTitle("Pick Alternate Application to Manage");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 5, 670, 185));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        manageAppButton.setText("Manage Selected Application");
        manageAppButton.setBounds(new Rectangle(245, 130, 200, 30));
        manageAppButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    manageAppButton_actionPerformed(e);
                }
            });
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(510, 130, 85, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        jLabel1.setText("Application Class");
        jLabel1.setBounds(new Rectangle(20, 55, 115, 30));
        jLabel1.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel1.setFont(new Font("Tahoma", 0, 14));
        appClassComboBox.setBounds(new Rectangle(145, 55, 510, 30));
        jLabel9.setText("Pick an Application ID / Application Class to Manage");
        jLabel9.setBounds(new Rectangle(15, 10, 645, 40));
        jLabel9.setFont(new Font("Tahoma", 0, 16));
        jLabel9.setHorizontalAlignment(SwingConstants.CENTER);
        connSuccessLabel.setBounds(new Rectangle(175, 315, 540, 35));
        connSuccessLabel.setFont(new Font("Tahoma", 0, 14));
        connSuccessLabel.setForeground(Color.blue);
        jLabel2.setText("Be aware that you do not necessarily have privileges to manage applications appearing here.");
        jLabel2.setBounds(new Rectangle(25, 95, 630, 30));
        jLabel2.setHorizontalAlignment(SwingConstants.CENTER);
        jLabel2.setFont(new Font("Tahoma", 0, 12));
        functionPanel.add(jLabel2, null);
        functionPanel.add(connSuccessLabel, null);
        functionPanel.add(appClassComboBox, null);
        functionPanel.add(jLabel1, null);
        functionPanel.add(closeButton, null);
        functionPanel.add(manageAppButton, null);
        functionPanel.add(jLabel9, null);
        this.getContentPane().add(functionPanel, null);
    }

    private void this_windowClosing(WindowEvent e) {
        OracleJavaSecure.closeConnection();
        parent.setVisible(true);
        this.setVisible(false);
    }

    private void closeButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void dataInit() throws Exception {
        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = conn.createStatement();
            
              // This code can be used to test and see who you are
            rs =
          stmt.executeQuery("SELECT USER, SYS_CONTEXT('USERENV','PROXY_USER') " +
                   ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                   ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                   ", SYS_CONTEXT('USERENV','OS_USER') " +
                   ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                   ", SYS_CONTEXT('USERENV','TERMINAL') " +
                   ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                   " FROM DUAL");
            if (rs.next()) {
                System.out.println("user                 : " +
                                   rs.getString(1));
                System.out.println("userenv proxy_user   : " +
                                   rs.getString(2));
                System.out.println("userenv current_user : " +
                                   rs.getString(3));
                System.out.println("userenv session_user : " +
                                   rs.getString(4));
                System.out.println("userenv os_user      : " +
                                   rs.getString(5));
                System.out.println("userenv ip_address   : " +
                                   rs.getString(6));
                System.out.println("userenv terminal     : " +
                                   rs.getString(7));
                System.out.println("userenv client_id    : " +
                                   rs.getString(8));
            }
            if (rs != null)
                rs.close();
            rs = stmt.executeQuery("SELECT * FROM sys.session_roles");
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
            if (rs != null)
                rs.close();
            
            // Note:  These static queries are not sensitive
            // yet still require appver_admin to execute
            // This first one is also filtered per user by dynamic where clause
            rs =
                    // by selecting also from appsec.v_app_conn_registry_filtered, only see those I can edit
                    stmt.executeQuery("SELECT DISTINCT application_id || '/' || class_name o FROM appsec.v_app_class_id " +
                                      "where class_name in ( select distinct class_name from appsec.v_app_conn_registry_filtered ) " +
                                      "ORDER BY o");
            appClassComboBox.removeAllItems();
            appClassComboBox.addItem("");
            while (rs.next()) {
                appClassComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();
        } catch (Exception x) {
            System.out.println(x.toString());
            x.printStackTrace();
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (Exception y) {
            }
        }
    }

    private void manageAppButton_actionPerformed(ActionEvent e) {
        try {
            if (0 == appClassComboBox.getSelectedIndex())
                return;
            String appId = (String)appClassComboBox.getSelectedItem();
            int place = appId.indexOf("/");
            String appClass = appId.substring(place + 1);
            appId = appId.substring(0, place);
            /*
             * Hints:
             * Use of Runtime.exec() is straightforward - more fine-grain environment control with ProcessBuilder
             * Use javaw.exe instead of java.exe - windowless means we don't have to deal with output stream
             * still deal with error stream!
             * Give full paths to javaw, ojdbc5.jar and the parent directory of orajavsec
             */
            Runtime rt = Runtime.getRuntime();
            Process proc =
                rt.exec("C:/Java/jdk1.6.0_24/bin/javaw -classpath " +
                        "C:/dev/mywork/OraJavSecure/Chapter12Single;C:/dev/ojdbc6.jar " +
                        "orajavsec.OJSAdmin " + appId + " " + appClass);
            BufferedReader stdError =
                new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            String inLine;
            while ((inLine = stdError.readLine()) != null) {
                System.out.println(inLine);
            }

        } catch (Exception x) {
            x.printStackTrace();
            JOptionPane.showMessageDialog(thisComponent,
                                          "Cannot start new process to manage application!");
        }
    }
}
