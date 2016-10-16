// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12
// Modify call to getAAConnRole() with correct Oracle instance name

// Note: Unfinished List buttons - intent was to show all users with each proxy grant
// Note: No key exchange required for this functional screen
package orajavsec;

import java.awt.Color;
import java.awt.Dimension;

import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import java.sql.ResultSet;
import java.sql.Statement;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import javax.swing.SwingUtilities;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;

public class AdminUsers extends JFrame {
    JFrame thisComponent = this;
    static JFrame parent;
    static OracleConnection conn;
    static String userID;

    private JPanel functionPanel = new JPanel();
    private JButton closeButton = new JButton();
    private JComboBox userComboBox = new JComboBox();
    private JLabel jLabel1 = new JLabel();
    private JCheckBox ojsaadmCheckBox = new JCheckBox();
    private JCheckBox appusrCheckBox = new JCheckBox();
    private JCheckBox avadminCheckBox = new JCheckBox();
    private JButton superListButton = new JButton();
    private JButton userAdmListButton = new JButton();
    private JButton appUserButton = new JButton();
    private JButton appRegButton = new JButton();
    private JButton editAppStrgsButton = new JButton();
    private JButton saveButton = new JButton();
    private JButton revokeUserButton = new JButton();
    private JLabel jLabel2 = new JLabel();

    public AdminUsers(JFrame parent) {
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

    public AdminUsers() {
        try {
            jbInit();
            conn = OracleJavaSecure.getAAConnRole("orcl", "ojsaadm");
            dataInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(503, 261));
        this.setTitle("Manage Administrative Users");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 5, 465, 200));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(345, 150, 100, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        userComboBox.setBounds(new Rectangle(120, 10, 260, 30));
        userComboBox.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    userComboBox_actionPerformed(e);
                }
            });
        jLabel1.setText("User");
        jLabel1.setBounds(new Rectangle(75, 10, 55, 30));
        ojsaadmCheckBox.setText("Assign Admin, Assign Apps to Users (ojsaadm)");
        ojsaadmCheckBox.setBounds(new Rectangle(110, 80, 335, 30));
        ojsaadmCheckBox.setOpaque(false);
        appusrCheckBox.setText("User Admin (appusr)");
        appusrCheckBox.setBounds(new Rectangle(110, 50, 335, 30));
        appusrCheckBox.setOpaque(false);
        avadminCheckBox.setText("App Register, Edit/Copy App Strings (avadmin)");
        avadminCheckBox.setBounds(new Rectangle(110, 110, 335, 30));
        avadminCheckBox.setOpaque(false);
        superListButton.setText("List");
        superListButton.setBounds(new Rectangle(290, 50, 65, 25));
        superListButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    superListButton_actionPerformed(e);
                }
            });
        userAdmListButton.setText("List");
        userAdmListButton.setBounds(new Rectangle(290, 80, 65, 25));
        userAdmListButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    userAdmListButton_actionPerformed(e);
                }
            });
        appUserButton.setText("List");
        appUserButton.setBounds(new Rectangle(290, 110, 65, 25));
        appUserButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    appUserButton_actionPerformed(e);
                }
            });
        appRegButton.setText("List");
        appRegButton.setBounds(new Rectangle(290, 140, 65, 25));
        appRegButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    appRegButton_actionPerformed(e);
                }
            });
        editAppStrgsButton.setText("List");
        editAppStrgsButton.setBounds(new Rectangle(290, 170, 65, 25));
        editAppStrgsButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    editAppStrgsButton_actionPerformed(e);
                }
            });
        saveButton.setText("Save Updates");
        saveButton.setBounds(new Rectangle(190, 150, 140, 30));
        saveButton.setActionCommand("Save Updates");
        saveButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    saveButton_actionPerformed(e);
                }
            });
        revokeUserButton.setText("Revoke User Access");
        revokeUserButton.setBounds(new Rectangle(20, 150, 155, 30));
        revokeUserButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    revokeUserButton_actionPerformed(e);
                }
            });
        //functionPanel.add(editAppStrgsButton, null);
        //functionPanel.add(appRegButton, null);
        //functionPanel.add(appUserButton, null);
        //functionPanel.add(userAdmListButton, null);
        //functionPanel.add(superListButton, null);
        jLabel2.setText("Use this app -->");
        jLabel2.setBounds(new Rectangle(10, 115, 95, 20));
        functionPanel.add(jLabel2, null);
        functionPanel.add(revokeUserButton, null);
        functionPanel.add(saveButton, null);
        functionPanel.add(avadminCheckBox, null);
        functionPanel.add(appusrCheckBox, null);
        functionPanel.add(ojsaadmCheckBox, null);
        functionPanel.add(jLabel1, null);
        functionPanel.add(userComboBox, null);
        functionPanel.add(closeButton, null);
        this.getContentPane().add(functionPanel, null);
    }

    private void this_windowClosing(WindowEvent e) {
        OracleJavaSecure.closeConnection();
        parent.setVisible(true);
        this.setVisible(false);
    }

    private void userComboBox_actionPerformed(ActionEvent e) {
        // When action from dataInit() at removeAllItems(), getItemCount() = 0
        if (0 == userComboBox.getItemCount() ||
            0 == userComboBox.getSelectedIndex()) {
            blankAll();
            return;
        }
        userID =
                Utility.pullIDFromParens((String)userComboBox.getSelectedItem());
        blankAll();
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    Statement stmt = null;
                    ResultSet rs = null;
                    try {
                        stmt = conn.createStatement();
                        // This requires ojs_adm_admin to execute
                        rs =
 stmt.executeQuery("SELECT INSTANCE, proxy, client " +
                   "FROM ojsaadm.instance_proxy_users ");
                        while (rs.next()) {
                            if (rs.getString(3).equalsIgnoreCase(userID)) {
                                if (rs.getString(2).equalsIgnoreCase("OJSAADM"))
                                    ojsaadmCheckBox.setSelected(true);
                                if (rs.getString(2).equalsIgnoreCase("APPUSR"))
                                    appusrCheckBox.setSelected(true);
                                if (rs.getString(2).equalsIgnoreCase("AVADMIN"))
                                    avadminCheckBox.setSelected(true);
                            }
                        }
                        if (rs != null)
                            rs.close();
                    } catch (Exception x) {
                        //System.out.println(x.toString());
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

    private void saveButton_actionPerformed(ActionEvent e) {
        // Ignore action unless selected user
        if (0 == userComboBox.getSelectedIndex()) {
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    userID =
                            Utility.pullIDFromParens((String)userComboBox.getSelectedItem());
                    OracleCallableStatement stmt = null;
                    try {
                        // First, try to create user on both instances
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_create_user_once(?)");
                        stmt.setString(1, userID);
                        stmt.executeUpdate();
                        if (stmt != null)
                            stmt.close();
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_create_user_many(?)");
                        stmt.setString(1, userID);
                        stmt.executeUpdate();
                        if (stmt != null)
                            stmt.close();
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL ojsaadm.apver_usr_adm_pkg.p_create_apver_user(?)");
                        stmt.setString(1, userID);
                        stmt.executeUpdate();
                        if (stmt != null)
                            stmt.close();
                        // Next, grant or revoke each proxy
                        if (ojsaadmCheckBox.isSelected()) {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_set_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "OJSAADM");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                        } else {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_drop_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "OJSAADM");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                        }
                        if (appusrCheckBox.isSelected()) {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_set_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "APPUSR");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                        } else {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_drop_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "APPUSR");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                        }
                        if (avadminCheckBox.isSelected()) {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_set_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "AVADMIN");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL ojsaadm.apver_usr_adm_pkg.p_set_apver_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "AVADMIN");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL ojsaadm.apver_usr_adm_pkg.p_grant_apver_appver_conns(?)");
                            stmt.setString(1, userID);
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                        } else {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_drop_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "AVADMIN");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL ojsaadm.apver_usr_adm_pkg.p_drop_apver_proxy_through(?,?)");
                            stmt.setString(1, userID);
                            stmt.setString(2, "AVADMIN");
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL ojsaadm.apver_usr_adm_pkg.p_revoke_apver_appver_conns(?)");
                            stmt.setString(1, userID);
                            stmt.executeUpdate();
                            if (stmt != null)
                                stmt.close();
                        }
                        blankAll();
                        userComboBox.setSelectedIndex(0);
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

    private void revokeUserButton_actionPerformed(ActionEvent e) {
        // Ignore action unless selected user
        if (0 == userComboBox.getSelectedIndex()) {
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    userID =
                            Utility.pullIDFromParens((String)userComboBox.getSelectedItem());
                    OracleCallableStatement stmt = null;
                    Statement stmt2 = null;
                    ResultSet rs = null;
                    try {
                        stmt2 = conn.createStatement();
                        // This requires ojs_adm_admin to execute
                        rs =
 stmt2.executeQuery("SELECT INSTANCE, proxy, client " +
                    "FROM ojsaadm.instance_proxy_users ");
                        while (rs.next()) {
                            if (rs.getString(3).equalsIgnoreCase(userID)) {
                                if (rs.getString(1).equalsIgnoreCase("apver")) {
                                    stmt =
(OracleCallableStatement)conn.prepareCall("CALL ojsaadm.apver_usr_adm_pkg.p_drop_apver_proxy_through(?,?)");
                                } else {
                                    stmt =
(OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_drop_proxy_through(?,?)");
                                }
                                stmt.setString(1, userID);
                                stmt.setString(2, rs.getString(1));
                                stmt.executeUpdate();
                                if (stmt != null)
                                    stmt.close();
                            }
                        }
                        if (rs != null)
                            rs.close();
                        blankAll();
                        userComboBox.setSelectedIndex(0);
                    } catch (Exception x) {
                        x.printStackTrace();
                        JOptionPane.showMessageDialog(thisComponent,
                                                      x.toString());
                    } finally {
                        try {
                            if (stmt2 != null)
                                stmt2.close();
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

    private void closeButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void blankAll() {
        ojsaadmCheckBox.setSelected(false);
        appusrCheckBox.setSelected(false);
        avadminCheckBox.setSelected(false);
    }

    private void dataInit() throws Exception {
        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = conn.createStatement();
            // Note:  This static (non-dynamic) query is not sensitive
            // yet still requires ojs_adm_admin to execute
            rs =
 stmt.executeQuery("SELECT e.last_name || ', ' || e.first_name || ' (' || u.user_id || ')' " +
                   "FROM hr.v_employees_public e, hr.v_emp_mobile_nos u " +
                   "where u.employee_id = e.employee_id " +
                   "ORDER BY e.last_name");
            // This throws event to run userComboBox_actionPerformed() method
            // Calls blankAll()
            userComboBox.removeAllItems();
            userComboBox.addItem("");
            userComboBox.setSelectedIndex(0);
            while (rs.next()) {
                userComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();
        } catch (Exception x) {
            System.out.println(x.toString());
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (Exception y) {
            }
        }
    }

    private void superListButton_actionPerformed(ActionEvent e) {
    }

    private void userAdmListButton_actionPerformed(ActionEvent e) {
    }

    private void appUserButton_actionPerformed(ActionEvent e) {
    }

    private void appRegButton_actionPerformed(ActionEvent e) {
    }

    private void editAppStrgsButton_actionPerformed(ActionEvent e) {
    }
}
