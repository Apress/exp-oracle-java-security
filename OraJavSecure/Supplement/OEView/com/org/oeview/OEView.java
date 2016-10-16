// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Supplement

package com.org.oeview;

import java.awt.Rectangle;

import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import oracle.jdbc.OracleConnection;

public class OEView extends JFrame {
    static OracleConnection conn = null;
    static DefaultTableModel oeViewTM = new DefaultTableModel();
    static Vector columnIdentifiers = new Vector();
    static {
        columnIdentifiers.add("CUSTOMER_ID");
        columnIdentifiers.add("CUST_FIRST_NAME");
        columnIdentifiers.add("CUST_LAST_NAME");
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

    private JScrollPane jScrollPane1 = new JScrollPane();
    // Make oeViewTable package access (default) so available to OEViewDialog
    //private 
    JTable oeViewTable = new JTable();

    public static void main(String[] args) {
        new OEView();
    }

    public OEView() {
        try {
            jbInit();
            dataInit();
            this.setVisible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(677, 498));
        this.setTitle("Order Entry Customers View");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        jScrollPane1.setBounds(new Rectangle(10, 10, 650, 450));
        jScrollPane1.getViewport().add(oeViewTable, null);
        this.getContentPane().add(jScrollPane1, null);
        oeViewTable.setModel(oeViewTM);
        oeViewTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        oeViewTable.addMouseListener(new MouseAdapter() {
                public void mouseClicked(MouseEvent e) {
                    oeViewTable_mouseClicked(e);
                }
            });
    }

    void dataInit() {
        Statement stmt = null;
        ResultSet rs = null;
        try {
            if (conn == null) {
                String password =
                    JOptionPane.showInputDialog(this, "Enter OE Customers Password: ");
                conn =
(OracleConnection)DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:orcl",
                                              "oe", password);
            }
            stmt = conn.createStatement();
            rs =
 stmt.executeQuery("SELECT CUSTOMER_ID, CUST_FIRST_NAME, CUST_LAST_NAME, CUST_ADDRESS, " +
                   "PHONE_NUMBERS, NLS_LANGUAGE, NLS_TERRITORY, CREDIT_LIMIT, CUST_EMAIL, " +
                   "ACCOUNT_MGR_ID, CUST_GEO_LOCATION, TO_CHAR( DATE_OF_BIRTH, 'MM/DD/YYYY' ), MARITAL_STATUS, " +
                   "GENDER, INCOME_LEVEL FROM OE.customers ORDER BY CUSTOMER_ID");
            // dataVector must be Vector of Vectors
            Vector dataVector = new Vector();
            Vector itemVector;
            while (rs.next()) {
                itemVector = new Vector();
                itemVector.add(rs.getString(1));
                itemVector.add(rs.getString(2));
                itemVector.add(rs.getString(3));
                itemVector.add(rs.getString(4));
                itemVector.add(rs.getString(5));
                itemVector.add(rs.getString(6));
                itemVector.add(rs.getString(7));
                itemVector.add(rs.getString(8));
                itemVector.add(rs.getString(9));
                itemVector.add(rs.getString(10));
                itemVector.add(rs.getString(11));
                itemVector.add(rs.getString(12));
                itemVector.add(rs.getString(13));
                itemVector.add(rs.getString(14));
                itemVector.add(rs.getString(15));
                dataVector.add(itemVector);
            }
            if (rs != null)
                rs.close();
            oeViewTM.setDataVector(dataVector, columnIdentifiers);
        } catch (Exception x) {
            x.printStackTrace();
            JOptionPane.showMessageDialog(this, x.toString());
            this_windowClosing(null);
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (Exception y) {
            }
        }
    }

    private void this_windowClosing(WindowEvent e) {
        try {
            this.setVisible(false);
            conn.close();
        } catch (Exception x) {
        }
        System.exit(0);
    }

    private void oeViewTable_mouseClicked(MouseEvent e) {
        OEViewDialog mOEVD = new OEViewDialog();
        mOEVD.setValues(this);
    }
}
