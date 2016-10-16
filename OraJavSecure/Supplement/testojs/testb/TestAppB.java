// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Supplement

package testojs.testb;

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

public class TestAppB extends JFrame {
    JFrame thisComponent = this;
    static OracleConnection conn;
    static SimpleDateFormat hDateFormat = new SimpleDateFormat("MM/dd/yy");
    static DefaultTableModel employeesTM = new DefaultTableModel();
    static Vector columnIdentifiers = new Vector();
    static {
        columnIdentifiers.add("last_name");
        columnIdentifiers.add("first_name");
        columnIdentifiers.add("emp_id");
        columnIdentifiers.add("email");
        columnIdentifiers.add("phone");
        columnIdentifiers.add("hire_date");
        columnIdentifiers.add("job_id");
        columnIdentifiers.add("salary");
        columnIdentifiers.add("commis_%");
        columnIdentifiers.add("mgr_id");
        columnIdentifiers.add("dept_id");
    }

    private static String locModulus;
    private static String locExponent;
    private static RAW sessionSecretDESSalt;
    private static RAW sessionSecretDESIterationCount;
    private static RAW sessionSecretDESAlgorithm;
    private static RAW sessionSecretDESPassPhrase = null;

    private JPanel topMenuPanel = new JPanel();
    private JScrollPane jScrollPane1 = new JScrollPane();
    private JTable employeesTable = new JTable();

    public static void main(String[] args) {
        new TestAppB();
    }

    public TestAppB() {
        try {
            jbInit();
            ojsInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void ojsInit() throws Exception {
        new Login(this);
        conn = OracleJavaSecure.getAAConnRole("orcl", "appusr");
        locModulus = OracleJavaSecure.getLocRSAPubMod();
        locExponent = OracleJavaSecure.getLocRSAPubExp();
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
        this.setTitle("Employees");
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

                    int errNo;
                    String errMsg;
                    OracleCallableStatement stmt = null;
                    OracleResultSet rs = null;
                    try {
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL hr.hr_sec_pkg.p_select_employees_sensitive(?,?,?,?,?,?,?,?,?)");
                        stmt.registerOutParameter(3, OracleTypes.RAW);
                        stmt.registerOutParameter(4, OracleTypes.RAW);
                        stmt.registerOutParameter(5, OracleTypes.RAW);
                        stmt.registerOutParameter(6, OracleTypes.RAW);
                        stmt.registerOutParameter(7, OracleTypes.CURSOR);
                        stmt.registerOutParameter(8, OracleTypes.NUMBER);
                        stmt.registerOutParameter(9, OracleTypes.VARCHAR);
                        stmt.setString(1, locModulus);
                        stmt.setString(2, locExponent);
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
                                                          "Oracle error p_select_employees_sensitive) " +
                                                          errNo + ", " +
                                                          errMsg);
                        } else {
                            sessionSecretDESSalt = stmt.getRAW(3);
                            sessionSecretDESIterationCount = stmt.getRAW(4);
                            sessionSecretDESAlgorithm = stmt.getRAW(5);
                            sessionSecretDESPassPhrase = stmt.getRAW(6);
                            rs = (OracleResultSet)stmt.getCursor(7);

                            Vector dataVector = new Vector();
                            Vector itemVector;
                            java.sql.Date sDate;
                            Date hDate;
                            while (rs.next()) {
                                itemVector = new Vector();
                                itemVector.add(rs.getString(3));
                                itemVector.add(rs.getString(2));
                                itemVector.add(rs.getString(1));
                                itemVector.add(rs.getString(4));
                                itemVector.add(rs.getString(5));
                                sDate = rs.getDate(6);
                                hDate = new Date(sDate.getTime());
                                itemVector.add(hDateFormat.format(hDate));
                                itemVector.add(rs.getString(7));
                                itemVector.add(OracleJavaSecure.getDecryptData(rs.getRAW(8),
                                                                               sessionSecretDESPassPhrase,
                                                                               sessionSecretDESAlgorithm,
                                                                               sessionSecretDESSalt,
                                                                               sessionSecretDESIterationCount));
                                itemVector.add(OracleJavaSecure.getDecryptData(rs.getRAW(9),
                                                                               sessionSecretDESPassPhrase,
                                                                               sessionSecretDESAlgorithm,
                                                                               sessionSecretDESSalt,
                                                                               sessionSecretDESIterationCount));
                                itemVector.add(rs.getString(10));
                                itemVector.add(rs.getString(11));
                                dataVector.add(itemVector);
                            }
                            if (rs != null)
                                rs.close();
                            employeesTM.setDataVector(dataVector,
                                                      columnIdentifiers);
                        }
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
