// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Supplement

package testojs.testc;

import java.awt.*;

import java.awt.event.*;

import java.sql.ResultSet;
import java.sql.Statement;

import java.text.SimpleDateFormat;

import java.util.Date;

import java.util.Vector;

import javax.swing.*;

import javax.swing.JScrollPane;

import javax.swing.JTable;

import javax.swing.table.DefaultTableModel;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;

import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

import orajavsec.OracleJavaSecure;

public class TestAppC extends JFrame {
    JFrame thisComponent = this;
    static OracleConnection conn;
    static SimpleDateFormat bDateFormat = new SimpleDateFormat("MM/dd/yy");
    static DefaultTableModel employeesTM = new DefaultTableModel();
    static Vector columnIdentifiers = new Vector();
    static {
        columnIdentifiers.add("CUST_LAST_NAME");
        columnIdentifiers.add("CUST_FIRST_NAME");
        columnIdentifiers.add("CUSTOMER_ID");
        columnIdentifiers.add("CUST_ADDRESS");
        columnIdentifiers.add("PHONE_NUMBERS");
        columnIdentifiers.add("NLS_LANGUAGE");
        columnIdentifiers.add("NLS_TERRITORY");
        columnIdentifiers.add("CREDIT_LIMIT");
        columnIdentifiers.add("CUST_EMAIL");
        columnIdentifiers.add("ACCOUNT_MGR_ID");
        columnIdentifiers.add("CUST_GEO_LOCATION");
        columnIdentifiers.add("DATE_OF_BIRTH");
        columnIdentifiers.add("MARITAL_STATUS");
        columnIdentifiers.add("GENDER");
        columnIdentifiers.add("INCOME_LEVEL");
    }

    private JPanel topMenuPanel = new JPanel();
    private JScrollPane jScrollPane1 = new JScrollPane();
    private JTable employeesTable = new JTable();

    public static void main(String[] args) {
        new TestAppC();
    }

    public TestAppC() {
        try {
            jbInit();
            ojsInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void ojsInit() throws Exception {
        new Login(this);
        conn = OracleJavaSecure.getAAConnRole("orcl", "oeview");
        dataInit();
        Login.center(this);
        this.setVisible(true);
        if (null == conn) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Your account is not permitted to use this application!");
            this_windowClosing(null);
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(631, 415));
        this.setTitle("Customers");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        topMenuPanel.setBounds(new Rectangle(5, 5, 595, 360));
        topMenuPanel.setLayout(null);
        topMenuPanel.setBackground(new Color(214, 255, 255));
        jScrollPane1.setBounds(new Rectangle(10, 20, 575, 330));
        employeesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        jScrollPane1.getViewport().add(employeesTable, null);
        topMenuPanel.add(jScrollPane1, null);
        this.getContentPane().add(topMenuPanel, null);
        employeesTable.setModel(employeesTM);
    }

    private void this_windowClosing(WindowEvent e) {
        System.exit(0);
    }

    private void dataInit() throws Exception {
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {

                    Statement stmt = null;
                    ResultSet rs = null;
                    try {
                        stmt = conn.createStatement();
                        rs =
 stmt.executeQuery("select * from oe.v_customer_detail");

                        Vector dataVector = new Vector();
                        Vector itemVector;
                        java.sql.Date bDate;
                        Date hDate;
                        while (rs.next()) {
                            itemVector = new Vector();
                            itemVector.add(rs.getString(3));
                            itemVector.add(rs.getString(2));
                            itemVector.add(rs.getString(1));
                            itemVector.add(rs.getString(4));
                            itemVector.add(rs.getString(5));
                            itemVector.add(rs.getString(6));
                            itemVector.add(rs.getString(7));
                            itemVector.add(rs.getString(8));
                            itemVector.add(rs.getString(9));
                            itemVector.add(rs.getString(10));
                            itemVector.add(rs.getString(11));
                            bDate = rs.getDate(12);
                            hDate = new Date(bDate.getTime());
                            itemVector.add(bDateFormat.format(hDate));
                            itemVector.add(rs.getString(13));
                            itemVector.add(rs.getString(14));
                            itemVector.add(rs.getString(15));
                            dataVector.add(itemVector);
                        }
                        if (rs != null)
                            rs.close();
                        employeesTM.setDataVector(dataVector,
                                                  columnIdentifiers);
                    } catch (Exception x) {
                        x.printStackTrace();
                    } finally {
                        try {
                            if (stmt != null)
                                stmt.close();
                        } catch (Exception y) {
                        }
                    }
                    Login.sayWaitDialog.setVisible(false);
                    employeesTM.fireTableDataChanged();
                }
            });
        // Ask the user to be patient while working
        Login.sayWaitDialog.setVisible(true);
    }
}
