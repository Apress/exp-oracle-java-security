// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12, modified for Single, conn to orcl
// Modify call to getAAConnRole() with correct Oracle instance name
// To Bootstrap OJSAdmin, uncomment lines in default constructor
// Calling putAppConnString() and PutAppConnections()
// For first two executions of this code.
// Be sure to delete embedded password from this file thereafter

/*
 * Test this by :
 * Delete row in orcl/appsec.v_application_admins for testojs.TestOracleJavaSecure$AnyNameWeWant
 * Delete row in orcl/appsec.v_app_class_id for testojs.TestOracleJavaSecure$AnyNameWeWant
 * Delete row(s) in orcl/appsec.v_app_conn_registry for testojs.TestOracleJavaSecure$AnyNameWeWant
 * Delete row(s) in appsec.v_application_registry for HRVIEW
 * commit
 * Enter these values on form: HRVIEW, APPUSR, HRVIEW_ROLE, testojs, TestOracleJavaSecure, AnyNameWeWant
 * Assure rows are re-created in all views, above
 * Run PickAppManage and then EditAppConns Functional Screens to insert
 * a connection string for HRVIEW - e.g., orcl, appusr, password, localhost, 1521
 * Edit, compile and run Chapter12/testojs.TestOracleJavaSecure
 */

// Note: No key exchange in assumed context for this functional screen
package orajavsec;

import java.awt.Color;
import java.awt.Dimension;

import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import javax.swing.SwingUtilities;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleTypes;

public class RegNewApp extends JFrame {
    JFrame thisComponent = this;
    boolean registerButtonPressed = false;
    static JFrame parent;
    static OracleConnection conn;
    static int employeeID;

    private JPanel functionPanel = new JPanel();
    private JLabel jLabel1 = new JLabel();
    private JLabel jLabel2 = new JLabel();
    private JLabel jLabel3 = new JLabel();
    private JTextField packageTextField = new JTextField();
    private JTextField classTextField = new JTextField();
    private JTextField innerClassTextField = new JTextField();
    private JLabel jLabel4 = new JLabel();
    private JTextField applicationIDTextField = new JTextField();
    private JButton registerButton = new JButton();
    private JButton closeButton = new JButton();
    private JLabel registerNote1Label = new JLabel();
    private JLabel registerNote2Label = new JLabel();
    private JLabel jLabel7 = new JLabel();
    private JLabel jLabel8 = new JLabel();
    private JTextField applicationUserTextField = new JTextField();
    private JTextField applicationRoleTextField = new JTextField();
    private JSeparator jSeparator1 = new JSeparator();
    private JButton createTemplateButton = new JButton();

    public RegNewApp(JFrame parent) {
        this();
        this.parent = parent;
        // Post jbInit visual setup
        createTemplateButton.setVisible(false);
        registerNote1Label.setVisible(false);
        registerNote2Label.setVisible(false);
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

    public RegNewApp() {
        try {
            jbInit();
            // First two times through, way to build conn string list
            //OracleJavaSecure.putAppConnString("orcl", "avadmin", "password",
            //    "localhost", String.valueOf(1521));
            //OracleJavaSecure.putAppConnections();
            conn = OracleJavaSecure.getAAConnRole("orcl", "avadmin");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(419, 433));
        this.setTitle("Register New Application");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 5, 385, 370));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        jLabel1.setText("package");
        jLabel1.setBounds(new Rectangle(10, 135, 110, 25));
        jLabel1.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel1.setFont(new Font("Tahoma", 0, 14));
        jLabel2.setText("Class");
        jLabel2.setBounds(new Rectangle(10, 165, 110, 25));
        jLabel2.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel2.setFont(new Font("Tahoma", 0, 14));
        jLabel3.setText("InnerClass");
        jLabel3.setBounds(new Rectangle(10, 230, 110, 25));
        jLabel3.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel3.setFont(new Font("Tahoma", 0, 14));
        packageTextField.setBounds(new Rectangle(130, 135, 240, 25));
        classTextField.setBounds(new Rectangle(130, 165, 240, 25));
        classTextField.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    classTextField_keyReleased(e);
                }
            });
        innerClassTextField.setBounds(new Rectangle(130, 230, 240, 25));
        jLabel4.setText("Application ID");
        jLabel4.setBounds(new Rectangle(5, 15, 110, 25));
        jLabel4.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel4.setFont(new Font("Tahoma", 0, 14));
        applicationIDTextField.setBounds(new Rectangle(130, 15, 240, 25));
        registerButton.setText("Register");
        registerButton.setBounds(new Rectangle(115, 275, 120, 30));
        registerButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    registerButton_actionPerformed(e);
                }
            });
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(280, 275, 85, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        registerNote1Label.setText("Note:  This functional screen changes context to");
        registerNote1Label.setBounds(new Rectangle(5, 310, 375, 30));
        registerNote1Label.setForeground(Color.red);
        registerNote1Label.setFont(new Font("Tahoma", 0, 14));
        registerNote1Label.setHorizontalAlignment(SwingConstants.CENTER);
        registerNote2Label.setText("register app.  Exit button will stop this Java GUI.");
        registerNote2Label.setBounds(new Rectangle(5, 330, 375, 30));
        registerNote2Label.setForeground(Color.red);
        registerNote2Label.setFont(new Font("Tahoma", 0, 14));
        registerNote2Label.setHorizontalAlignment(SwingConstants.CENTER);
        jLabel7.setText("App User");
        jLabel7.setBounds(new Rectangle(5, 45, 110, 25));
        jLabel7.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel7.setFont(new Font("Tahoma", 0, 14));
        jLabel8.setText("App Role");
        jLabel8.setBounds(new Rectangle(5, 75, 110, 25));
        jLabel8.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel8.setFont(new Font("Tahoma", 0, 14));
        applicationUserTextField.setBounds(new Rectangle(130, 45, 240, 25));
        applicationRoleTextField.setBounds(new Rectangle(130, 75, 240, 25));
        jSeparator1.setBounds(new Rectangle(15, 115, 355, 2));
        createTemplateButton.setText("Create App \nClass on Oracle From Login Template");
        createTemplateButton.setBounds(new Rectangle(25, 195, 345, 30));
        createTemplateButton.setActionCommand("Create App Class on Oracle From Login Template");
        createTemplateButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    createTemplateButton_actionPerformed(e);
                }
            });
        functionPanel.add(createTemplateButton, null);
        functionPanel.add(jSeparator1, null);
        functionPanel.add(applicationRoleTextField, null);
        functionPanel.add(applicationUserTextField, null);
        functionPanel.add(jLabel8, null);
        functionPanel.add(jLabel7, null);
        functionPanel.add(registerNote2Label, null);
        functionPanel.add(registerNote1Label, null);
        functionPanel.add(closeButton, null);
        functionPanel.add(registerButton, null);
        functionPanel.add(applicationIDTextField, null);
        functionPanel.add(jLabel4, null);
        functionPanel.add(innerClassTextField, null);
        functionPanel.add(classTextField, null);
        functionPanel.add(packageTextField, null);
        functionPanel.add(jLabel3, null);
        functionPanel.add(jLabel2, null);
        functionPanel.add(jLabel1, null);
        this.getContentPane().add(functionPanel, null);
    }

    private void this_windowClosing(WindowEvent e) {
        OracleJavaSecure.closeConnection();
        if (registerButtonPressed)
            System.exit(0);
        parent.setVisible(true);
        this.setVisible(false);
    }

    private void closeButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void classTextField_keyReleased(KeyEvent e) {
        if (classTextField.getText().equals("Login"))
            createTemplateButton.setVisible(true);
        else
            createTemplateButton.setVisible(false);
    }

    private void blankAll() {
        applicationIDTextField.setText("");
        packageTextField.setText("");
        classTextField.setText("");
        innerClassTextField.setText("");
    }


    private void registerButton_actionPerformed(ActionEvent e) {
        // not null fields
        if (applicationIDTextField.getText().equals("") ||
            applicationUserTextField.getText().equals("") ||
            applicationRoleTextField.getText().equals("") ||
            packageTextField.getText().equals("") ||
            classTextField.getText().equals("") ||
            innerClassTextField.getText().equals("")) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Must have values for all fields!");
            return;
        }
        registerNote1Label.setVisible(true);
        registerNote2Label.setVisible(true);
        closeButton.setText("Exit");
        registerButtonPressed = true;
        ///*
        Statement stmt2 = null;
        ResultSet rs2 = null;
        try {
            stmt2 = conn.createStatement();
            rs2 =
stmt2.executeQuery("SELECT USER, SYS_CONTEXT('USERENV','PROXY_USER') " +
                   ", SYS_CONTEXT('USERENV','CURRENT_USER') " +
                   ", SYS_CONTEXT('USERENV','SESSION_USER') " +
                   ", SYS_CONTEXT('USERENV','OS_USER') " +
                   ", SYS_CONTEXT('USERENV','IP_ADDRESS') " +
                   ", SYS_CONTEXT('USERENV','TERMINAL') " +
                   ", SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') " +
                   " FROM DUAL");
            if (rs2.next()) {
                System.out.println("user                 : " +
                                   rs2.getString(1));
                System.out.println("userenv proxy_user   : " +
                                   rs2.getString(2));
                System.out.println("userenv current_user : " +
                                   rs2.getString(3));
                System.out.println("userenv session_user : " +
                                   rs2.getString(4));
                System.out.println("userenv os_user      : " +
                                   rs2.getString(5));
                System.out.println("userenv ip_address   : " +
                                   rs2.getString(6));
                System.out.println("userenv terminal     : " +
                                   rs2.getString(7));
                System.out.println("userenv client_id    : " +
                                   rs2.getString(8));
            }
            if (rs2 != null)
                rs2.close();
            rs2 = stmt2.executeQuery("SELECT * FROM sys.session_roles");
            while (rs2.next()) {
                System.out.println(rs2.getString(1));
            }
            if (rs2 != null)
                rs2.close();
        } catch (Exception x) {
            x.printStackTrace();
        } finally {
            try {
                if (stmt2 != null)
                    stmt2.close();
            } catch (Exception y) {
            }
        }
        //*/

        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    Statement stmt = null;
                    try {
                        String innerClassName = packageTextField.getText();
                        if (innerClassName.endsWith("."))
                            innerClassName.substring(0,
                                                     innerClassName.length() -
                                                     1);
                        innerClassName =
                                innerClassName + "." + classTextField.getText() +
                                "$" + innerClassTextField.getText();
                        Class classToRegister = Class.forName(innerClassName);

                        Object appClass = classToRegister.newInstance();
                        // If we got this far, class must be OK and on CLASSPATH

                        // Quite possibly you have already inserted these
                        // Dont want unique constraint exception thrown
                        try {
                            String updateString =
                                "insert into appsec.v_application_admins " +
                                "( class_name, user_id ) values ( ?, " +
                                "SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ))";
                            // Only appver_admin can insert into appsec.v_application_admins
                            PreparedStatement pstmt =
                                conn.prepareStatement(updateString);
                            pstmt.setString(1, innerClassName);
                            pstmt.executeUpdate();
                        } catch (Exception y) {
                            System.out.println("a: " + y.toString());
                        }

                        try {
                            String updateString =
                                "insert into appsec.v_app_class_id " +
                                "( class_name, application_id ) values ( ?, ? )";
                            // Only appver_admin can insert into appsec.v_app_class_id
                            PreparedStatement pstmt =
                                conn.prepareStatement(updateString);
                            pstmt.setString(1, innerClassName);
                            pstmt.setString(2,
                                            applicationIDTextField.getText().toUpperCase());
                            pstmt.executeUpdate();
                        } catch (Exception y) {
                            System.out.println("b: " + y.toString());
                        }

                        try {
                            String updateString =
                                "insert into appsec.v_application_registry " +
                                "( application_id, app_user, app_role ) values ( ?, ?, ? )";
                            // Only appver_admin can insert into appsec.v_application_registry
                            PreparedStatement pstmt =
                                conn.prepareStatement(updateString);
                            pstmt.setString(1,
                                            applicationIDTextField.getText().toUpperCase());
                            pstmt.setString(2,
                                            applicationUserTextField.getText().toUpperCase());
                            pstmt.setString(3,
                                            applicationRoleTextField.getText().toUpperCase());
                            pstmt.executeUpdate();
                        } catch (Exception y) {
                            System.out.println("c: " + y.toString());
                        }

                        try {
                            String updateString =
                                "BEGIN sys.appver_conns_role_pkg.p_grant_appver_conns_role( " +
                                "SYS_CONTEXT( 'USERENV', 'CLIENT_IDENTIFIER' ) ); END;";
                            PreparedStatement pstmt =
                                conn.prepareStatement(updateString);
                            pstmt.executeUpdate();
                        } catch (Exception y) {
                            System.out.println("d: " + y.toString());
                        }

                        // Switching contexts to target application in order to register it
                        // We do not have key exchange
                        // So we cant decrypt / encrypt connection strings
                        // OK, since there are none at this point
                        // Requires update OracleJavaSecure.setDecryptConns
                        OracleJavaSecure.setAppContext(applicationIDTextField.getText().toUpperCase(),
                                                       appClass, "");

                        OracleJavaSecure.getAppConnections();

                        OracleJavaSecure.putAppConnections();

                    } catch (Exception x) {
                        x.printStackTrace();
                        JOptionPane.showMessageDialog(thisComponent,
                                                      x.toString());
                    } finally {
                        try {
                            if (stmt != null)
                                stmt.close();
                        } catch (Exception y) {
                        }
                    }
                    Login.sayWaitDialog.setVisible(false);
                }
            });
        // Ask the user to be patient while working
        Login.sayWaitDialog.setVisible(true);
    }

    private void createTemplateButton_actionPerformed(ActionEvent e) {
        if (packageTextField.getText().equals("")) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Must have a package!");
            return;
        }
        innerClassTextField.setText("InnerRevLvlClass");
        /*
        Statement stmt2 = null;
        try {
            stmt2 = conn.createStatement();
            ResultSet rs =
                stmt2.executeQuery("SELECT USER, SYS_CONTEXT('USERENV','PROXY_USER') " +
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
            rs = stmt2.executeQuery("SELECT * FROM sys.session_roles");
            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
            if (rs != null)
                rs.close();

        } catch (Exception x) {
            x.printStackTrace();
        } finally {
            try {
                if (stmt2 != null)
                    stmt2.close();
            } catch (Exception y) {
            }
        }
        */

        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    OracleCallableStatement stmt = null;
                    int errNo;
                    String errMsg;
                    try {
                        // This will test whether we have specified class corrrectly
                        // and have it on our CLASSPATH
                        Class.forName(packageTextField.getText() +
                                      ".Login$InnerRevLvlClass");
                        // To use this procedure, must grant CREATE PROCEDURE to appsec
                        stmt =
(OracleCallableStatement)conn.prepareCall("call appsec.appsec_admin_pkg.p_create_template_class( ?,?,? )");
                        stmt.registerOutParameter(2, OracleTypes.NUMBER);
                        stmt.registerOutParameter(3, OracleTypes.VARCHAR);
                        stmt.setString(1,
                                       packageTextField.getText() + ".Login$InnerRevLvlClass");
                        System.out.println(packageTextField.getText() +
                                           ".Login$InnerRevLvlClass");
                        stmt.setInt(2, 0);
                        stmt.setNull(3, OracleTypes.VARCHAR);
                        stmt.executeUpdate();

                        errNo = stmt.getInt(2);
                        if (errNo != 0) {
                            errMsg = stmt.getString(3);
                            JOptionPane.showMessageDialog(thisComponent,
                                                          "Oracle error p_create_template_class) " +
                                                          errNo + ", " +
                                                          errMsg);
                        }
                    } catch (Exception x) {
                        //System.out.println(x.toString());
                        Login.sayWaitDialog.setVisible(false);
                        JOptionPane.showMessageDialog(thisComponent,
                                                      x.toString());
                        x.printStackTrace();
                    } finally {
                        try {
                            if (stmt != null)
                                stmt.close();
                        } catch (Exception y) {
                        }
                    }
                    Login.sayWaitDialog.setVisible(false);
                }
            });
        // Ask the user to be patient while working
        Login.sayWaitDialog.setVisible(true);
    }
}
