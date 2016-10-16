// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12
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

import java.sql.ResultSet;
import java.sql.Statement;

import java.text.SimpleDateFormat;

import java.util.Date;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import javax.swing.SwingUtilities;

import oracle.jdbc.OracleCallableStatement;
import oracle.jdbc.OracleConnection;
import oracle.jdbc.OracleResultSet;
import oracle.jdbc.OracleTypes;

import oracle.sql.RAW;

public class AddUser extends JFrame {
    JFrame thisComponent = this;
    static JFrame parent;
    static OracleConnection conn;
    static SimpleDateFormat hDateFormat = new SimpleDateFormat("MM/dd/yy");
    static int employeeID;

    private static String locModulus;
    private static String locExponent;
    private static RAW sessionSecretDESSalt;
    private static RAW sessionSecretDESIterationCount;
    private static RAW sessionSecretDESAlgorithm;
    private static RAW sessionSecretDESPassPhrase = null;

    private JPanel functionPanel = new JPanel();
    private JButton closeButton = new JButton();
    private JLabel jLabel1 = new JLabel();
    private JTextField eMailNameTextField = new JTextField();
    private JTextField phoneNumberTextField = new JTextField();
    private JTextField hireDateTextField = new JTextField();
    private JLabel jLabel2 = new JLabel();
    private JLabel jLabel3 = new JLabel();
    private JLabel jLabel4 = new JLabel();
    private JLabel jLabel5 = new JLabel();
    private JTextField firstNameTextField = new JTextField();
    private JTextField lastNameTextField = new JTextField();
    private JTextField salaryTextField = new JTextField();
    private JTextField commissionPctTextField = new JTextField();
    private JLabel jLabel6 = new JLabel();
    private JLabel jLabel7 = new JLabel();
    private JLabel jLabel8 = new JLabel();
    private JLabel jLabel9 = new JLabel();
    private JRadioButton existingEmpRadioButton = new JRadioButton();
    private JRadioButton newEmpRadioButton = new JRadioButton();
    private JLabel jLabel10 = new JLabel();
    private JLabel jLabel12 = new JLabel();
    private JComboBox jobIDComboBox = new JComboBox();
    private JComboBox managerIDComboBox = new JComboBox();
    private JComboBox deptIDComboBox = new JComboBox();
    private JComboBox existingEmpComboBox = new JComboBox();
    private JSeparator jSeparator1 = new JSeparator();
    private JTextField osUserIDTextField = new JTextField();
    private JLabel jLabel13 = new JLabel();
    private JTextField pagerNumberTextField = new JTextField();
    private JTextField smsPhoneNumberTextField = new JTextField();
    private JComboBox smsCarrierCodeComboBox = new JComboBox();
    private JLabel jLabel14 = new JLabel();
    private JLabel jLabel15 = new JLabel();
    private JLabel jLabel16 = new JLabel();
    private JSeparator jSeparator2 = new JSeparator();
    private JButton saveButton = new JButton();
    private JLabel userMessageLabel = new JLabel();
    private JLabel userMessageLabel1 = new JLabel();

    public AddUser(JFrame parent) {
        this();
        this.parent = parent;
        // Post jbInit visual setup
        userMessageLabel.setVisible(false);
        userMessageLabel1.setVisible(false);
        ButtonGroup empGroup = new ButtonGroup();
        empGroup.add(existingEmpRadioButton);
        empGroup.add(newEmpRadioButton);
        existingEmpRadioButton.setSelected(true);
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

    public AddUser() {
        try {
            jbInit();
            conn = OracleJavaSecure.getAAConnRole("orcl", "appusr");
            // Possibly reentering - need new keys for new Oracle session
            OracleJavaSecure.resetKeys();
            locModulus = OracleJavaSecure.getLocRSAPubMod();
            locExponent = OracleJavaSecure.getLocRSAPubExp();
            sessionSecretDESPassPhrase = null;
            dataInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(400, 416));
        this.setTitle("Add / Edit Application User");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 5, 380, 370));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(300, 335, 75, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        jLabel1.setText("jLabel1");
        jLabel1.setBounds(new Rectangle(80, 5, 50, 20));
        eMailNameTextField.setBounds(new Rectangle(130, 95, 120, 25));
        phoneNumberTextField.setBounds(new Rectangle(255, 95, 120, 25));
        hireDateTextField.setBounds(new Rectangle(5, 140, 120, 25));
        jLabel2.setText("Phone Number");
        jLabel2.setBounds(new Rectangle(255, 75, 120, 20));
        jLabel3.setText("E-Mail Name");
        jLabel3.setBounds(new Rectangle(130, 75, 120, 20));
        jLabel4.setText("Hire M/D/YY [today]");
        jLabel4.setBounds(new Rectangle(5, 120, 120, 20));
        jLabel5.setText("Job ID");
        jLabel5.setBounds(new Rectangle(5, 75, 120, 20));
        firstNameTextField.setBounds(new Rectangle(130, 50, 120, 25));
        lastNameTextField.setBounds(new Rectangle(255, 50, 120, 25));
        salaryTextField.setBounds(new Rectangle(130, 140, 120, 25));
        commissionPctTextField.setBounds(new Rectangle(255, 140, 120, 25));
        jLabel6.setText("First Name");
        jLabel6.setBounds(new Rectangle(130, 30, 120, 20));
        jLabel7.setText("Last Name");
        jLabel7.setBounds(new Rectangle(255, 30, 120, 20));
        jLabel8.setText("Commission %");
        jLabel8.setBounds(new Rectangle(255, 120, 120, 20));
        jLabel9.setText("Monthly Salary");
        jLabel9.setBounds(new Rectangle(130, 120, 120, 20));
        existingEmpRadioButton.setText("Existing Employee ID");
        existingEmpRadioButton.setBounds(new Rectangle(5, 5, 145, 20));
        existingEmpRadioButton.setBackground(new Color(255, 247, 214));
        existingEmpRadioButton.setSelected(true);
        existingEmpRadioButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    existingEmpRadioButton_actionPerformed(e);
                }
            });
        newEmpRadioButton.setText("New Employee");
        newEmpRadioButton.setBounds(new Rectangle(5, 50, 115, 20));
        newEmpRadioButton.setBackground(new Color(255, 247, 214));
        newEmpRadioButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    newEmpRadioButton_actionPerformed(e);
                }
            });
        jLabel10.setText("Manager ID");
        jLabel10.setBounds(new Rectangle(5, 165, 120, 20));
        jLabel12.setText("Department ID");
        jLabel12.setBounds(new Rectangle(255, 165, 120, 20));
        jobIDComboBox.setBounds(new Rectangle(5, 95, 120, 25));
        managerIDComboBox.setBounds(new Rectangle(5, 185, 245, 25));
        deptIDComboBox.setBounds(new Rectangle(255, 185, 120, 25));
        existingEmpComboBox.setBounds(new Rectangle(155, 5, 220, 25));
        existingEmpComboBox.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    existingEmpComboBox_actionPerformed(e);
                }
            });
        jSeparator1.setBounds(new Rectangle(40, 220, 300, 2));
        osUserIDTextField.setBounds(new Rectangle(130, 245, 120, 25));
        jLabel13.setText("OS User ID");
        jLabel13.setBounds(new Rectangle(130, 225, 120, 20));
        pagerNumberTextField.setBounds(new Rectangle(255, 245, 120, 25));
        smsPhoneNumberTextField.setBounds(new Rectangle(5, 290, 185, 25));
        smsCarrierCodeComboBox.setBounds(new Rectangle(195, 290, 180, 25));
        jLabel14.setText("Pager Number");
        jLabel14.setBounds(new Rectangle(255, 225, 120, 20));
        jLabel15.setText("SMS Phone Number");
        jLabel15.setBounds(new Rectangle(5, 270, 185, 20));
        jLabel16.setText("SMS Carrier Code");
        jLabel16.setBounds(new Rectangle(195, 270, 145, 20));
        jSeparator2.setBounds(new Rectangle(40, 325, 300, 2));
        saveButton.setText("Save Updates");
        saveButton.setBounds(new Rectangle(150, 335, 130, 30));
        saveButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    saveButton_actionPerformed(e);
                }
            });
        userMessageLabel.setForeground(Color.red);
        userMessageLabel.setHorizontalAlignment(SwingConstants.CENTER);
        userMessageLabel.setFont(new Font("Tahoma", 0, 14));
        userMessageLabel.setBounds(new Rectangle(5, 225, 120, 25));
        userMessageLabel.setText("Create Employee");
        userMessageLabel1.setForeground(Color.red);
        userMessageLabel1.setHorizontalAlignment(SwingConstants.CENTER);
        userMessageLabel1.setFont(new Font("Tahoma", 0, 14));
        userMessageLabel1.setBounds(new Rectangle(5, 245, 120, 25));
        userMessageLabel1.setText("Then User");
        functionPanel.add(userMessageLabel1, null);
        functionPanel.add(saveButton, null);
        functionPanel.add(jSeparator2, null);
        functionPanel.add(jSeparator1, null);
        functionPanel.add(existingEmpComboBox, null);
        functionPanel.add(deptIDComboBox, null);
        functionPanel.add(managerIDComboBox, null);
        functionPanel.add(jobIDComboBox, null);
        functionPanel.add(jLabel12, null);
        functionPanel.add(jLabel10, null);
        functionPanel.add(newEmpRadioButton, null);
        functionPanel.add(existingEmpRadioButton, null);
        functionPanel.add(jLabel9, null);
        functionPanel.add(jLabel8, null);
        functionPanel.add(jLabel7, null);
        functionPanel.add(jLabel6, null);
        functionPanel.add(commissionPctTextField, null);
        functionPanel.add(salaryTextField, null);
        functionPanel.add(lastNameTextField, null);
        functionPanel.add(firstNameTextField, null);
        functionPanel.add(jLabel5, null);
        functionPanel.add(jLabel4, null);
        functionPanel.add(jLabel3, null);
        functionPanel.add(jLabel2, null);
        functionPanel.add(hireDateTextField, null);
        functionPanel.add(phoneNumberTextField, null);
        functionPanel.add(eMailNameTextField, null);
        functionPanel.add(jLabel1, null);
        functionPanel.add(closeButton, null);
        functionPanel.add(jLabel13, null);
        functionPanel.add(smsPhoneNumberTextField, null);
        functionPanel.add(smsCarrierCodeComboBox, null);
        functionPanel.add(jLabel16, null);
        functionPanel.add(jLabel15, null);
        functionPanel.add(userMessageLabel, null);
        functionPanel.add(osUserIDTextField, null);
        functionPanel.add(pagerNumberTextField, null);
        functionPanel.add(jLabel14, null);
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

    private void blankAll() {
        firstNameTextField.setText("");
        lastNameTextField.setText("");
        salaryTextField.setText("");
        commissionPctTextField.setText("");
        eMailNameTextField.setText("");
        phoneNumberTextField.setText("");
        hireDateTextField.setText("");
        try {
            // At initialization, this is called but combo items are not populated
            jobIDComboBox.setSelectedIndex(0);
            managerIDComboBox.setSelectedIndex(0);
            deptIDComboBox.setSelectedIndex(0);
            blankUser();
        } catch (Exception x) {
        }
    }

    private void blankUser() {
        userMessageLabel.setVisible(false);
        userMessageLabel1.setVisible(false);
        osUserIDTextField.setText("");
        pagerNumberTextField.setText("");
        smsPhoneNumberTextField.setText("");
        smsCarrierCodeComboBox.setSelectedIndex(0);
    }

    private void existingEmpRadioButton_actionPerformed(ActionEvent e) {
        userMessageLabel.setVisible(false);
        userMessageLabel1.setVisible(false);
        existingEmpComboBox.setEnabled(true);
        firstNameTextField.setEnabled(false);
        lastNameTextField.setEnabled(false);
        hireDateTextField.setEnabled(false);
    }

    private void newEmpRadioButton_actionPerformed(ActionEvent e) {
        // This calls blankAll()
        existingEmpComboBox.setSelectedIndex(0);
        userMessageLabel.setVisible(true);
        userMessageLabel1.setVisible(true);
        existingEmpComboBox.setEnabled(false);
        firstNameTextField.setEnabled(true);
        lastNameTextField.setEnabled(true);
        hireDateTextField.setEnabled(true);
        osUserIDTextField.setEnabled(false);
    }

    private void existingEmpComboBox_actionPerformed(ActionEvent e) {
        /*
        try {
            throw new Exception("Exception to see were event came from");
        } catch (Exception x) {
            x.printStackTrace();
        }
        System.out.println("event:" + e.toString());
        */
        // When action from dataInit() at removeAllItems(), getItemCount() = 0
        if (0 == existingEmpComboBox.getItemCount() ||
            0 == existingEmpComboBox.getSelectedIndex()) {
            osUserIDTextField.setEnabled(false);
            blankAll();
            return;
        }
        employeeID =
                Integer.parseInt(Utility.pullIDFromParens((String)existingEmpComboBox.getSelectedItem()));
        blankAll();
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    int errNo;
                    String errMsg;
                    OracleCallableStatement stmt = null;
                    OracleResultSet rs = null;
                    try {
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL hr.hr_sec_pkg.p_select_employee_by_id_sens(?,?,?,?,?,?,?,?,?,?)");
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
                        stmt.setInt(10, employeeID);
                        stmt.executeUpdate();

                        errNo = stmt.getInt(8);
                        if (errNo != 0) {
                            errMsg = stmt.getString(9);
                            JOptionPane.showMessageDialog(thisComponent,
                                                          "Oracle error p_select_employee_by_id_sens) " +
                                                          errNo + ", " +
                                                          errMsg);
                        } else {
                            sessionSecretDESSalt = stmt.getRAW(3);
                            sessionSecretDESIterationCount = stmt.getRAW(4);
                            sessionSecretDESAlgorithm = stmt.getRAW(5);
                            sessionSecretDESPassPhrase = stmt.getRAW(6);
                            rs = (OracleResultSet)stmt.getCursor(7);
                            // Should be only one record for this Employee ID
                            if (rs.next()) {
                                firstNameTextField.setText(rs.getString(2));
                                lastNameTextField.setText(rs.getString(3));
                                eMailNameTextField.setText(rs.getString(4));
                                phoneNumberTextField.setText(rs.getString(5));
                                // Our stored procedure passes Hire Date back as sql.Date
                                // So process here to format
                                java.sql.Date sDate = rs.getDate(6);
                                Date hDate = new Date(sDate.getTime());
                                hireDateTextField.setText(hDateFormat.format(hDate));
                                jobIDComboBox.setSelectedItem(rs.getString(7));
                                deptIDComboBox.setSelectedItem(rs.getString(11));
                                // Find this user's manager id in parentheses of combo box
                                for (int i = 0;
                                     i < managerIDComboBox.getItemCount();
                                     i++) {
                                    if (rs.getString(10).equals(Utility.pullIDFromParens((String)managerIDComboBox.getItemAt(i)))) {
                                        managerIDComboBox.setSelectedIndex(i);
                                        break;
                                    }
                                }
                                // Decrypt salary and commission pct using shared password key
                                salaryTextField.setText(OracleJavaSecure.getDecryptData(rs.getRAW(8),
                                                                                        sessionSecretDESPassPhrase,
                                                                                        sessionSecretDESAlgorithm,
                                                                                        sessionSecretDESSalt,
                                                                                        sessionSecretDESIterationCount));
                                commissionPctTextField.setText(OracleJavaSecure.getDecryptData(rs.getRAW(9),
                                                                                               sessionSecretDESPassPhrase,
                                                                                               sessionSecretDESAlgorithm,
                                                                                               sessionSecretDESSalt,
                                                                                               sessionSecretDESIterationCount));
                            }
                            if (rs != null)
                                rs.close();
                            if (stmt != null)
                                stmt.close();
                        }
                        // Select from mobile_nos where emp id
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL hr.hr_pub_pkg.p_select_emp_mobile_nos_by_id(?,?,?,?)");
                        stmt.registerOutParameter(2, OracleTypes.CURSOR);
                        stmt.registerOutParameter(3, OracleTypes.NUMBER);
                        stmt.registerOutParameter(4, OracleTypes.VARCHAR);
                        stmt.setInt(1, employeeID);
                        stmt.setInt(3, 0);
                        stmt.setNull(4, OracleTypes.VARCHAR);
                        stmt.executeUpdate();

                        errNo = stmt.getInt(3);
                        if (errNo != 0) {
                            errMsg = stmt.getString(4);
                            JOptionPane.showMessageDialog(thisComponent,
                                                          "Oracle error p_select_emp_mobile_nos_by_id) " +
                                                          errNo + ", " +
                                                          errMsg);
                        } else {
                            rs = (OracleResultSet)stmt.getCursor(2);
                            // Should be only one record for this Employee ID
                            if (rs.next()) {
                                // Will not let you change a user ID for an employee
                                osUserIDTextField.setEnabled(false);
                                osUserIDTextField.setText(rs.getString(1));
                                pagerNumberTextField.setText(rs.getString(2));
                                smsPhoneNumberTextField.setText(rs.getString(3));
                                smsCarrierCodeComboBox.setSelectedItem(rs.getString(4));
                            } else {
                                osUserIDTextField.setEnabled(true);
                            }
                            if (rs != null)
                                rs.close();
                            if (stmt != null)
                                stmt.close();
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
    }

    private void saveButton_actionPerformed(ActionEvent e) {
        // I have presumed you will not update hire date
        // If you intend to update job_id or department_id,
        //  modify hr.hr_sec_pkg.p_update_employees_sens
        // not null fields
        if (lastNameTextField.getText().equals("") ||
            jobIDComboBox.getSelectedIndex() == 0 ||
            eMailNameTextField.getText().equals("") ||
            managerIDComboBox.getSelectedIndex() == 0 ||
            deptIDComboBox.getSelectedIndex() == 0) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Must have values for Last Name, Job ID, E-Mail, Dept ID and Mgr ID!");
            return;
        }
        // Ignore user settings unless an existing employee
        // If existing employee and user ID is blank
        // but entered pager or sms phone, alert to error
        if (existingEmpComboBox.getSelectedIndex() > 0 &&
            osUserIDTextField.getText().equals("") &&
            (!(pagerNumberTextField.getText().equals("") &&
               smsPhoneNumberTextField.getText().equals("")))) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Must have value for User ID, else blank mobile nos!");
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    // presume no real employee_id = 0
                    if (existingEmpComboBox.getSelectedIndex() == 0)
                        employeeID = 0;
                    else
                        employeeID =
                                Integer.parseInt(Utility.pullIDFromParens((String)existingEmpComboBox.getSelectedItem()));
                    int errNo;
                    String errMsg;
                    OracleCallableStatement stmt = null;
                    try {
                        if (null == sessionSecretDESPassPhrase) {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL hr.hr_sec_pkg.p_get_shared_passphrase(?,?,?,?,?,?,?,?)");
                            stmt.registerOutParameter(3, OracleTypes.RAW);
                            stmt.registerOutParameter(4, OracleTypes.RAW);
                            stmt.registerOutParameter(5, OracleTypes.RAW);
                            stmt.registerOutParameter(6, OracleTypes.RAW);
                            stmt.registerOutParameter(7, OracleTypes.NUMBER);
                            stmt.registerOutParameter(8, OracleTypes.VARCHAR);
                            stmt.setString(1, locModulus);
                            stmt.setString(2, locExponent);
                            stmt.setNull(3, OracleTypes.RAW);
                            stmt.setNull(4, OracleTypes.RAW);
                            stmt.setNull(5, OracleTypes.RAW);
                            stmt.setNull(6, OracleTypes.RAW);
                            stmt.setInt(7, 0);
                            stmt.setNull(8, OracleTypes.VARCHAR);
                            stmt.executeUpdate();

                            errNo = stmt.getInt(7);
                            if (errNo != 0) {
                                errMsg = stmt.getString(8);
                                JOptionPane.showMessageDialog(thisComponent,
                                                              "Oracle error p_get_shared_passphrase) " +
                                                              errNo + ", " +
                                                              errMsg);
                            } else {
                                sessionSecretDESSalt = stmt.getRAW(3);
                                sessionSecretDESIterationCount =
                                        stmt.getRAW(4);
                                sessionSecretDESAlgorithm = stmt.getRAW(5);
                                sessionSecretDESPassPhrase = stmt.getRAW(6);
                                OracleJavaSecure.makeDESKey(sessionSecretDESPassPhrase,
                                                            sessionSecretDESAlgorithm,
                                                            sessionSecretDESSalt,
                                                            sessionSecretDESIterationCount);
                            }
                            if (null != stmt)
                                stmt.close();
                        }
                        stmt =
(OracleCallableStatement)conn.prepareCall("CALL hr.hr_sec_pkg.p_update_employees_sensitive(?,?,?,?,?,?,?,?,?,?,?,?,?)");
                        stmt.registerOutParameter(12, OracleTypes.NUMBER);
                        stmt.registerOutParameter(13, OracleTypes.VARCHAR);
                        stmt.setInt(1, employeeID);
                        stmt.setString(2, firstNameTextField.getText());
                        stmt.setString(3, lastNameTextField.getText());
                        stmt.setString(4,
                                       eMailNameTextField.getText().toUpperCase());
                        stmt.setString(5, phoneNumberTextField.getText());
                        // We must pass our stored procedure the Hire Date as sql.Date
                        // So process here to format
                        if (hireDateTextField.getText().equals("")) {
                            stmt.setDate(6,
                                         new java.sql.Date((new Date()).getTime()));
                        } else {
                            Date hDate =
                                hDateFormat.parse(hireDateTextField.getText());
                            stmt.setDate(6,
                                         new java.sql.Date(hDate.getTime()));
                        }
                        stmt.setString(7,
                                       (String)jobIDComboBox.getSelectedItem());
                        stmt.setRAW(8,
                                    OracleJavaSecure.getCryptData(salaryTextField.getText()));
                        stmt.setRAW(9,
                                    OracleJavaSecure.getCryptData(commissionPctTextField.getText()));
                        if (managerIDComboBox.getSelectedIndex() > 0) {
                            stmt.setInt(10,
                                        Integer.parseInt(Utility.pullIDFromParens((String)managerIDComboBox.getSelectedItem())));
                        } else
                            stmt.setInt(10, 0);
                        if (deptIDComboBox.getSelectedIndex() > 0) {
                            stmt.setInt(11,
                                        Integer.parseInt((String)deptIDComboBox.getSelectedItem()));
                        } else
                            stmt.setInt(11, 0);
                        stmt.setInt(12, 0);
                        stmt.setNull(13, OracleTypes.VARCHAR);
                        stmt.executeUpdate();
                        errNo = stmt.getInt(12);
                        if (errNo != 0) {
                            errMsg = stmt.getString(13);
                            JOptionPane.showMessageDialog(thisComponent,
                                                          "Oracle error p_update_employees_sensitive) " +
                                                          errNo + ", " +
                                                          errMsg);
                        }
                        if (null != stmt)
                            stmt.close();
                        if (existingEmpComboBox.getSelectedIndex() > 0 &&
                            (!osUserIDTextField.getText().equals(""))) {
                            stmt =
(OracleCallableStatement)conn.prepareCall("CALL hr.hr_pub_pkg.p_update_emp_mobile_nos(?,?,?,?,?,?,?)");
                            stmt.registerOutParameter(6, OracleTypes.NUMBER);
                            stmt.registerOutParameter(7, OracleTypes.VARCHAR);
                            stmt.setInt(1, employeeID);
                            stmt.setString(2,
                                           osUserIDTextField.getText().toUpperCase());
                            stmt.setString(3, pagerNumberTextField.getText());
                            stmt.setString(4,
                                           smsPhoneNumberTextField.getText());
                            stmt.setString(5,
                                           (String)smsCarrierCodeComboBox.getSelectedItem());
                            stmt.setInt(6, 0);
                            stmt.setNull(7, OracleTypes.VARCHAR);
                            stmt.executeUpdate();
                            errNo = stmt.getInt(6);
                            if (errNo != 0) {
                                errMsg = stmt.getString(7);
                                JOptionPane.showMessageDialog(thisComponent,
                                                              "Oracle error p_update_emp_mobile_nos) " +
                                                              errNo + ", " +
                                                              errMsg);
                            }
                        }
                        if (null != stmt)
                            stmt.close();
                        // This calls blankAll by way of existingEmpComboBox.removeAllItems();
                        dataInit();
                    } catch (Exception x) {
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

    private void dataInit() throws Exception {
        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = conn.createStatement();
            /*
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
          */
            // Note:  These static (non-dynamic) queries are not sensitive
            // yet still require hrview_role to execute
            // Also, there may be better sources for these lists,
            // we just use v_employees_public because we already configured it
            rs =
 stmt.executeQuery("SELECT last_name || ', ' || first_name || ' (' || employee_id || ')' " +
                   "FROM hr.v_employees_public ORDER BY last_name");
            // This throws event to run existingEmpComboBox_actionPerformed() method
            // Calls blankAll()
            existingEmpComboBox.removeAllItems();
            existingEmpComboBox.addItem("");
            while (rs.next()) {
                existingEmpComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();

            rs =
 stmt.executeQuery("SELECT DISTINCT job_id FROM hr.v_employees_public ORDER BY job_id");
            jobIDComboBox.removeAllItems();
            jobIDComboBox.addItem("");
            while (rs.next()) {
                jobIDComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();

            rs =
 stmt.executeQuery("SELECT DISTINCT department_id FROM hr.v_employees_public ORDER BY department_id");
            deptIDComboBox.removeAllItems();
            deptIDComboBox.addItem("");
            while (rs.next()) {
                deptIDComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();

            rs =
 stmt.executeQuery("SELECT last_name || ', ' || first_name || ' (' || employee_id || ')' " +
                   "FROM hr.v_employees_public WHERE employee_id IN ( " +
                   "SELECT DISTINCT manager_id FROM hr.v_employees_public ) " +
                   "ORDER BY last_name");
            managerIDComboBox.removeAllItems();
            managerIDComboBox.addItem("");
            while (rs.next()) {
                managerIDComboBox.addItem(rs.getString(1));
            }
            if (rs != null)
                rs.close();

            rs =
 stmt.executeQuery("SELECT sms_carrier_cd FROM hr.v_sms_carrier_host ORDER BY sms_carrier_cd");
            smsCarrierCodeComboBox.removeAllItems();
            smsCarrierCodeComboBox.addItem("");
            while (rs.next()) {
                smsCarrierCodeComboBox.addItem(rs.getString(1));
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
}
