// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12
// Modify call to getAAConnRole() with correct Oracle instance name
// Also remove call to ojsaadm.apver_usr_adm_pkg.p_create_apver_user

// Note: Unfinished, should also select Application and list possible/granted users
// Note: No key exchange required for this functional screen
package orajavsec;

import java.awt.Color;
import java.awt.Dimension;

import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import java.sql.ResultSet;
import java.sql.Statement;

import java.text.SimpleDateFormat;

import java.util.Date;

import java.util.Hashtable;
import java.util.Vector;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;

import javax.swing.SwingUtilities;

import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.table.DefaultTableModel;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

public class AssignApp extends JFrame {
    JFrame thisComponent = this;
    static JFrame parent;
    static OracleConnection conn;
    static String userID;
    static DefaultTableModel availableProxiesTM = new DefaultTableModel();
    static DefaultTableModel userProxiesTM = new DefaultTableModel();
    static DefaultTableModel appsTM = new DefaultTableModel();
    static Vector columnIdentifiers = new Vector();
    static {
        columnIdentifiers.add("Proxies");
    }
    static Vector appColumnIdentifiers = new Vector();
    static {
        appColumnIdentifiers.add("Applications");
    }
    static Hashtable<String, Vector> appsHashtable =
        new Hashtable<String, Vector>();

    private JPanel functionPanel = new JPanel();
    private JButton closeButton = new JButton();
    private JComboBox userComboBox = new JComboBox();
    private JButton saveButton = new JButton();
    private JScrollPane jScrollPane1 = new JScrollPane();
    private JScrollPane jScrollPane2 = new JScrollPane();
    private JLabel jLabel1 = new JLabel();
    private JLabel jLabel2 = new JLabel();
    private JLabel jLabel3 = new JLabel();
    private JTable availableProxiesTable = new JTable();
    private JTable userProxiesTable = new JTable();
    private JButton addButton = new JButton();
    private JButton removeButton = new JButton();
    private JLabel jLabel4 = new JLabel();
    private JScrollPane jScrollPane3 = new JScrollPane();
    private JTable appsListTable = new JTable();
    private JSeparator jSeparator2 = new JSeparator();

    public AssignApp(JFrame parent) {
        this();
        this.parent = parent;
        // Post jbInit visual setup
        availableProxiesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userProxiesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
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

    public AssignApp() {
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
        this.setSize(new Dimension(568, 435));
        this.setTitle("Grant/Revoke Application Proxy for Users");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 5, 535, 380));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(445, 335, 75, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        userComboBox.setBounds(new Rectangle(155, 5, 295, 25));
        userComboBox.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    userComboBox_actionPerformed(e);
                }
            });
        saveButton.setText("Save Updates");
        saveButton.setBounds(new Rectangle(295, 335, 130, 30));
        saveButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    saveButton_actionPerformed(e);
                }
            });
        jScrollPane1.setBounds(new Rectangle(155, 60, 170, 230));
        jScrollPane2.setBounds(new Rectangle(355, 60, 170, 230));
        jLabel1.setText("Available Proxies");
        jLabel1.setBounds(new Rectangle(160, 35, 160, 25));
        jLabel2.setText("Proxies for User");
        jLabel2.setBounds(new Rectangle(360, 35, 160, 25));
        jLabel3.setText("User");
        jLabel3.setBounds(new Rectangle(85, 5, 70, 25));
        availableProxiesTable.addMouseListener(new MouseAdapter() {
                public void mouseClicked(MouseEvent e) {
                    availableProxiesTable_mouseClicked(e);
                }
            });
        jScrollPane3.getViewport().add(appsListTable, null);
        functionPanel.add(jSeparator2, null);
        functionPanel.add(jScrollPane3, null);
        functionPanel.add(jLabel4, null);
        functionPanel.add(removeButton, null);
        functionPanel.add(addButton, null);
        functionPanel.add(jLabel3, null);
        functionPanel.add(jLabel2, null);
        functionPanel.add(jLabel1, null);
        jScrollPane1.getViewport().add(availableProxiesTable, null);
        functionPanel.add(jScrollPane1, null);
        functionPanel.add(saveButton, null);
        functionPanel.add(userComboBox, null);
        functionPanel.add(closeButton, null);
        jScrollPane2.getViewport().add(userProxiesTable, null);
        functionPanel.add(jScrollPane2, null);
        this.getContentPane().add(functionPanel, null);
        availableProxiesTable.setModel(availableProxiesTM);
        userProxiesTable.setModel(userProxiesTM);
        addButton.setText("Add Selected -->");
        addButton.setBounds(new Rectangle(170, 290, 155, 30));
        addButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    addButton_actionPerformed(e);
                }
            });
        removeButton.setText("<-- Remove Selected");
        removeButton.setBounds(new Rectangle(355, 290, 155, 30));
        removeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    removeButton_actionPerformed(e);
                }
            });
        jLabel4.setText("Applications for Proxy");
        jLabel4.setBounds(new Rectangle(15, 35, 140, 25));
        jScrollPane3.setBounds(new Rectangle(10, 60, 130, 230));
        appsListTable.setRowSelectionAllowed(false);
        appsListTable.setModel(appsTM);
        jSeparator2.setBounds(new Rectangle(335, 50, 10, 275));
    }

    private void this_windowClosing(WindowEvent e) {
        OracleJavaSecure.closeConnection();
        parent.setVisible(true);
        this.setVisible(false);
    }

    private void closeButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void userComboBox_actionPerformed(ActionEvent e) {
        // When action from dataInit() at removeAllItems(), getItemCount() = 0
        if (0 == userComboBox.getItemCount() ||
            0 == userComboBox.getSelectedIndex()) {
            Vector dataVector = new Vector();
            userProxiesTM.setDataVector(dataVector, columnIdentifiers);
            userProxiesTM.fireTableDataChanged();
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    userID =
                            Utility.pullIDFromParens((String)userComboBox.getSelectedItem());
                    Statement stmt = null;
                    ResultSet rs = null;
                    try {
                        stmt = conn.createStatement();
                        // Note:  This static (non-dynamic) query is not sensitive
                        // yet still requires ojs_adm_admin to execute
                        rs =
 stmt.executeQuery("SELECT DISTINCT p.proxy, p.client FROM ojsaadm.instance_proxy_users p " +
                   "WHERE p.instance <> 'APVER' " +
                   "AND p.proxy NOT IN ('APPVER','AVADMIN','APPSEC','OJSAADM') " +
                   "ORDER BY p.proxy");
                        // dataVector must be Vector of Vectors
                        Vector dataVector = new Vector();
                        Vector itemVector;
                        while (rs.next()) {
                            if (rs.getString(2).equals(userID)) {
                                itemVector = new Vector();
                                itemVector.add(rs.getString(1));
                                dataVector.add(itemVector);
                            }
                        }
                        if (rs != null)
                            rs.close();
                        userProxiesTM.setDataVector(dataVector,
                                                    columnIdentifiers);
                    } catch (Exception x) {
                        System.out.println(x.toString());
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

    private void addButton_actionPerformed(ActionEvent e) {
        if (availableProxiesTable.getSelectedRow() == -1)
            return;
        Vector dataVector = userProxiesTM.getDataVector();
        String value =
            (String)availableProxiesTM.getValueAt(availableProxiesTable.getSelectedRow(),
                                                  0);
        Vector itemVector = new Vector();
        itemVector.add(value);
        if (!dataVector.contains(itemVector)) {
            dataVector.add(itemVector);
            userProxiesTM.setDataVector(dataVector, columnIdentifiers);
        }
    }

    private void removeButton_actionPerformed(ActionEvent e) {
        if (userProxiesTable.getSelectedRow() == -1)
            return;
        Vector dataVector = userProxiesTM.getDataVector();
        String value =
            (String)userProxiesTM.getValueAt(userProxiesTable.getSelectedRow(),
                                             0);
        Vector itemVector = new Vector();
        itemVector.add(value);
        dataVector.remove(itemVector);
        userProxiesTM.setDataVector(dataVector, columnIdentifiers);
    }

    private void saveButton_actionPerformed(ActionEvent e) {
        // Ignore action unless selected user
        if (0 == userComboBox.getSelectedIndex()) {
            Vector dataVector = new Vector();
            userProxiesTM.setDataVector(dataVector, columnIdentifiers);
            userProxiesTM.fireTableDataChanged();
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    userID =
                            Utility.pullIDFromParens((String)userComboBox.getSelectedItem());
                    OracleCallableStatement stmt2 = null;
                    Statement stmt = null;
                    ResultSet rs = null;
                    try {
                        // First, try to create user on both instances
                        stmt2 =
                                (OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_create_user_once(?)");
                        stmt2.setString(1, userID);
                        stmt2.executeUpdate();
                        if (stmt2 != null)
                            stmt2.close();
                        stmt2 =
                                (OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_create_user_many(?)");
                        stmt2.setString(1, userID);
                        stmt2.executeUpdate();
                        if (stmt2 != null)
                            stmt2.close();
                        // Note:  This static (non-dynamic) query is not sensitive
                        // yet still requires ojs_adm_admin to execute
                        stmt = conn.createStatement();
                        rs =
 stmt.executeQuery("SELECT DISTINCT p.proxy, p.client FROM ojsaadm.instance_proxy_users p " +
                   "WHERE p.instance <> 'APVER' " +
                   "AND p.proxy NOT IN ('APPVER','AVADMIN','APPSEC','OJSAADM') " +
                   "ORDER BY p.proxy");
                        // dataVector must be Vector of Vectors
                        Vector dataVector = userProxiesTM.getDataVector();
                        Vector itemVector;
                        String proxyID;
                        while (rs.next()) {
                            if (rs.getString(2).equals(userID)) {
                                proxyID = rs.getString(1);
                                System.out.println(" user/proxy: " + userID +
                                                   "/" + proxyID);
                                itemVector = new Vector();
                                itemVector.add(proxyID);
                                if (dataVector.contains(itemVector)) {
                                    System.out.println("retaining proxy to: " +
                                                       proxyID);
                                    dataVector.remove(itemVector);
                                } else {
                                    // Remove proxy for user
                                    System.out.println("removing proxy to: " +
                                                       proxyID);
                                    stmt2 =
                                            (OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_drop_proxy_through(?,?)");
                                    stmt2.setString(1, userID);
                                    stmt2.setString(2, proxyID);
                                    stmt2.executeUpdate();
                                    if (stmt2 != null)
                                        stmt2.close();
                                }
                            }
                        }
                        if (rs != null)
                            rs.close();
                        for (Object element : dataVector) {
                            itemVector = (Vector)element;
                            proxyID = (String)itemVector.get(0);
                            // Add proxy for user
                            System.out.println("adding proxy to: " + proxyID);
                            stmt2 =
                                    (OracleCallableStatement)conn.prepareCall("CALL sys.usr_role_adm_pkg.p_set_proxy_through(?,?)");
                            stmt2.setString(1, userID);
                            stmt2.setString(2, proxyID);
                            stmt2.executeUpdate();
                            if (stmt2 != null)
                                stmt2.close();
                        }
                    } catch (Exception x) {
                        System.out.println(x.toString());
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

    private void availableProxiesTable_mouseClicked(MouseEvent e) {
        if (availableProxiesTable.getSelectedRow() == -1) {
            //Vector dataVector = new Vector();
            //appsTM.setDataVector(dataVector, appColumnIdentifiers);
            appsTM.setDataVector(null, appColumnIdentifiers);
            return;
        }
        String key =
            (String)availableProxiesTM.getValueAt(availableProxiesTable.getSelectedRow(),
                                                  0);
        Vector dataVector = appsHashtable.get(key);
        appsTM.setDataVector(dataVector, appColumnIdentifiers);
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
            userComboBox.removeAllItems();
            userComboBox.addItem("");
            while (rs.next()) {
                userComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();
            //stmt.executeQuery("SELECT DISTINCT a.application_id || ' (' || p.proxy || ')', a.application_id " +
            //"FROM ojsaadm.instance_proxy_users p, appsec.v_application_registry a " +
            //"WHERE p.instance <> 'APVER' " +
            //"AND p.proxy NOT IN ('APPVER','AVADMIN','APPSEC','OJSAADM') " +
            //"AND a.app_user = p.proxy ORDER BY a.application_id");
            rs =
 stmt.executeQuery("SELECT DISTINCT a.app_user FROM appsec.v_application_registry a " +
                   "WHERE a.app_user NOT IN ('APPVER','AVADMIN','APPSEC','OJSAADM') " +
                   // Do not filter by application_admins -- allow all with ojsadmin to update
                   //"AND a.application_id IN ( SELECT DISTINCT application_id FROM appsec.v_app_class_id " +
                   //"WHERE class_name IN ( SELECT DISTINCT class_name FROM v_app_conn_registry_filtered ) ) " +
                   "ORDER BY a.app_user");
            // dataVector must be Vector of Vectors
            Vector dataVector = new Vector();
            Vector itemVector;
            while (rs.next()) {
                itemVector = new Vector();
                itemVector.add(rs.getString(1));
                dataVector.add(itemVector);
            }
            if (rs != null)
                rs.close();
            availableProxiesTM.setDataVector(dataVector, columnIdentifiers);
            rs =
 stmt.executeQuery("SELECT DISTINCT a.application_id, p.proxy " +
                   "FROM ojsaadm.instance_proxy_users p, appsec.v_application_registry a " +
                   "WHERE p.instance <> 'APVER' " +
                   "AND p.proxy NOT IN ('APPVER','AVADMIN','APPSEC','OJSAADM') " +
                   "AND a.app_user = p.proxy ORDER BY a.application_id");
            // appsHashtable must be Hashtable of Vectors of Vectors
            // empty static Hashtable each time you enter this screen
            appsHashtable.clear();
            appsTM.setDataVector(null, appColumnIdentifiers);
            while (rs.next()) {
                if (appsHashtable.containsKey(rs.getString(2))) {
                    dataVector = appsHashtable.get(rs.getString(2));
                    itemVector = new Vector();
                    itemVector.add(rs.getString(1));
                    dataVector.add(itemVector);
                } else {
                    dataVector = new Vector();
                    itemVector = new Vector();
                    itemVector.add(rs.getString(1));
                    dataVector.add(itemVector);
                }
                appsHashtable.put(rs.getString(2), dataVector);
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
}
