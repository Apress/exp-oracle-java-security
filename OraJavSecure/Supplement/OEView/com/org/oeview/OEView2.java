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

import java.sql.ResultSet;
import java.sql.Statement;

import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;

import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import orajavsec.OracleJavaSecure;

public class OEView2 extends JFrame {
    JFrame thisComponent = this;

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
    // Make oeViewTable package access (default) so available to OEViewDialog2
    //private
    JTable oeViewTable = new JTable();

    public static void main(String[] args) {
        new OEView2();
    }

    public OEView2() {
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
                // Copy Login.java to com/org/oeview.  Set package. Give application_id = OEVIEW.
                // Assure you have OEView in the CLASSPATH when running OJSAdmin to register.
                new Login(this);
                // This static utility method centers any component on the screen
                Login.center(this);
                conn = OracleJavaSecure.getAAConnRole("orcl", "oeview");
            }
            /*
            stmt = conn.createStatement();
            rs =
 stmt.executeQuery("SELECT CUSTOMER_ID, CUST_FIRST_NAME, CUST_LAST_NAME, CUST_ADDRESS, " +
                   "PHONE_NUMBERS, NLS_LANGUAGE, NLS_TERRITORY, CREDIT_LIMIT, CUST_EMAIL, " +
                   "ACCOUNT_MGR_ID, CUST_GEO_LOCATION, TO_CHAR( DATE_OF_BIRTH, 'MM/DD/YYYY' ), MARITAL_STATUS, " +
                   "GENDER, INCOME_LEVEL FROM OE.customers ORDER BY CUSTOMER_ID");
            */

            // Call new procedures in oe.oe_sec_pkg to get and set data.
            SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        int errNo;
                        String errMsg;
                        OracleCallableStatement stmt = null;
                        OracleResultSet rs = null;
                        try {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL oe.oe_sec_pkg.p_select_customers_sensitive(?,?,?,?,?,?,?,?,?)");
                            stmt.registerOutParameter(3, OracleTypes.RAW);
                            stmt.registerOutParameter(4, OracleTypes.RAW);
                            stmt.registerOutParameter(5, OracleTypes.RAW);
                            stmt.registerOutParameter(6, OracleTypes.RAW);
                            stmt.registerOutParameter(7, OracleTypes.CURSOR);
                            stmt.registerOutParameter(8, OracleTypes.NUMBER);
                            stmt.registerOutParameter(9, OracleTypes.VARCHAR);
                            stmt.setString(1,
                                           OracleJavaSecure.getLocRSAPubMod());
                            stmt.setString(2,
                                           OracleJavaSecure.getLocRSAPubExp());
                            stmt.setNull(3, OracleTypes.RAW);
                            stmt.setNull(4, OracleTypes.RAW);
                            stmt.setNull(5, OracleTypes.RAW);
                            stmt.setNull(6, OracleTypes.RAW);
                            stmt.setInt(8, 0);
                            stmt.setNull(9, OracleTypes.VARCHAR);
                            stmt.executeUpdate();

                            errNo = stmt.getInt(8);
                            if (errNo != 0) {
                                errMsg = stmt.getString(9);
                                JOptionPane.showMessageDialog(thisComponent,
                                                              "Oracle error p_select_employee_by_id_sens) " +
                                                              errNo + ", " +
                                                              errMsg);
                            } else {
                                rs = (OracleResultSet)stmt.getCursor(7);

                                // Following code from previous version, with decryption added
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
                                    //itemVector.add(rs.getString(12));
                                    itemVector.add(OracleJavaSecure.getDecryptData(rs.getRAW(12),
                                                                                   stmt.getRAW(6),
                                                                                   stmt.getRAW(5),
                                                                                   stmt.getRAW(3),
                                                                                   stmt.getRAW(4)));
                                    //itemVector.add(rs.getString(13));
                                    itemVector.add(OracleJavaSecure.getDecryptData(rs.getRAW(13),
                                                                                   stmt.getRAW(6),
                                                                                   stmt.getRAW(5),
                                                                                   stmt.getRAW(3),
                                                                                   stmt.getRAW(4)));
                                    itemVector.add(rs.getString(14));
                                    //itemVector.add(rs.getString(15));
                                    itemVector.add(OracleJavaSecure.getDecryptData(rs.getRAW(15),
                                                                                   stmt.getRAW(6),
                                                                                   stmt.getRAW(5),
                                                                                   stmt.getRAW(3),
                                                                                   stmt.getRAW(4)));
                                    dataVector.add(itemVector);
                                }
                                if (rs != null)
                                    rs.close();
                                oeViewTM.setDataVector(dataVector,
                                                       columnIdentifiers);
                            }

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
            // It may take a while to get the user data, esp while we set up encryption
            // So ask the user to be patient while working
            Login.sayWaitDialog.setVisible(true);

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
        OEViewDialog2 mOEVD = new OEViewDialog2();
        mOEVD.setValues(this);
    }
}
