// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Supplement

// Include this Login dialog in each application

// Each new application will have to have a different package
// Else you will have to change the inner class name
package com.org.oeview;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Frame;

import java.awt.Rectangle;

import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import java.io.Serializable;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import orajavsec.OracleJavaSecure;
import orajavsec.RevLvlClassIntfc;

public class Login extends JDialog {
    private JPanel jPanel1 = new JPanel();
    private JLabel jLabel1 = new JLabel();
    private JLabel jLabel2 = new JLabel();
    private JTextField twoFactCodeTextField = new JTextField();
    private JButton continueButton = new JButton();
    private JLabel reEnterLabel = new JLabel();

    // ApplicationID is unique to this application - modify for other applications
    private static String applicationID = "OEVIEW";
    private static Object appClass = new InnerRevLvlClass();
    private JLabel jLabel3 = new JLabel();
    private JLabel appIDLabel = new JLabel();

    private void this_windowClosing(WindowEvent e) {
        System.exit(0);
    }

    private void twoFactCodeTextField_actionPerformed(ActionEvent e) {
        continueButton_actionPerformed(null);
    }

    public static class InnerRevLvlClass implements Serializable,
                                                    RevLvlClassIntfc {
        private static final long serialVersionUID = 2011010100L;
        private String innerClassRevLvl = "20110101a";

        public String getRevLvl() {
            return innerClassRevLvl;
        }
    }

    public Login() {
        this(null, "", false);
    }

    public Login(Frame parent, String title, boolean modal) {
        super(parent, title, modal);
        try {
            jbInit();
            ojsInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Login(Frame parent) {
        // For Oracle Java Secure, call this constructor
        this(parent, "2-Factor Authentication Login", true);
    }

    public Login(Frame parent, String applicationID, String appClassName) {
        // This replacement constructor is used when managing a selected application
        super(parent, "2-Factor Authentication Login", true);
        try {
            this.applicationID = applicationID;
            Class applicationClass = Class.forName(appClassName);
            appClass = applicationClass.newInstance();
            jbInit();
            ojsInit();
        } catch (Exception e) {
            System.out.println("Specified application class is not available");
            System.exit(0);
        }
    }

    private void ojsInit() {
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    OracleJavaSecure.setAppContext(applicationID, appClass,
                                                   "");
                    // Under some circumstances, this will throw an exception
                    // if OS User not allowed, also test isAppverOK
                    OracleJavaSecure.getAppConnections();
                    // on success, original error message will be blanked out
                    if (OracleJavaSecure.isAppverOK())
                        twoFactCodeTextField.setText("");
                    Login.sayWaitDialog.setVisible(false);
                }
            });
        Login.sayWaitDialog.setVisible(true);
        Login.center(this);
        reEnterLabel.setVisible(false);
        appIDLabel.setText(applicationID);
        this.setVisible(true);
        return;
    }

    private void jbInit() throws Exception {
        this.setSize(new Dimension(376, 211));
        this.getContentPane().setLayout(null);
        this.setTitle("2-Factor Authentication Login");
        this.setModal(true);
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        jPanel1.setBounds(new Rectangle(5, 5, 345, 155));
        jPanel1.setBackground(new Color(231, 255, 214));
        jPanel1.setLayout(null);
        jLabel1.setText("A 2-Factor Auth Code has been sent to you.");
        jLabel1.setBounds(new Rectangle(10, 10, 325, 25));
        jLabel1.setFont(new Font("Tahoma", 1, 14));
        jLabel2.setText("Enter it here when you receive it.");
        jLabel2.setBounds(new Rectangle(10, 35, 325, 25));
        jLabel2.setFont(new Font("Tahoma", 1, 14));
        twoFactCodeTextField.setBounds(new Rectangle(10, 90, 200, 30));
        twoFactCodeTextField.setText("Your OS User account cannot log in");
        twoFactCodeTextField.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    twoFactCodeTextField_actionPerformed(e);
                }
            });
        continueButton.setText("Continue");
        continueButton.setBounds(new Rectangle(235, 90, 95, 30));
        continueButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    continueButton_actionPerformed(e);
                }
            });
        reEnterLabel.setText("Retry or Exit and Re-Enter to Generate New 2-Factor Code");
        reEnterLabel.setBounds(new Rectangle(0, 120, 345, 25));
        reEnterLabel.setHorizontalAlignment(SwingConstants.CENTER);
        jLabel3.setText("App ID:");
        jLabel3.setBounds(new Rectangle(10, 60, 135, 25));
        jLabel3.setFont(new Font("Tahoma", 1, 14));
        jLabel3.setHorizontalAlignment(SwingConstants.RIGHT);
        appIDLabel.setBounds(new Rectangle(150, 60, 135, 25));
        appIDLabel.setFont(new Font("Tahoma", 1, 14));
        appIDLabel.setForeground(Color.blue);
        jPanel1.add(appIDLabel, null);
        jPanel1.add(jLabel3, null);
        jPanel1.add(reEnterLabel, null);
        jPanel1.add(continueButton, null);
        jPanel1.add(twoFactCodeTextField, null);
        jPanel1.add(jLabel2, null);
        jPanel1.add(jLabel1, null);
        this.getContentPane().add(jPanel1, null);
    }

    private void continueButton_actionPerformed(ActionEvent e) {
        if (twoFactCodeTextField.getText().equals("Bad 2-factor code"))
            twoFactCodeTextField.setText("");
        if (twoFactCodeTextField.getText().equals("") ||
            twoFactCodeTextField.getText().equals("Your OS User account cannot log in"))
            return;
        OracleJavaSecure.setAppContext(applicationID, appClass,
                                       twoFactCodeTextField.getText());
        OracleJavaSecure.getAppConnections();
        if (!OracleJavaSecure.test2Factor()) {
            twoFactCodeTextField.setText("Bad 2-factor code");
            reEnterLabel.setVisible(true);
            return;
        }
        this.setVisible(false);
        return;
    }

    public static void center(Component item) {
        // We almost always want our GUI screens to appear in the center of the monitor
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        Dimension frameSize = item.getSize();
        if (frameSize.height > screenSize.height) {
            frameSize.height = screenSize.height;
        }
        if (frameSize.width > screenSize.width) {
            frameSize.width = screenSize.width;
        }
        item.setLocation((screenSize.width - frameSize.width) / 2,
                         (screenSize.height - frameSize.height) / 2);
    }

    // We will use this whenever we expect a process duration to exceed user patience
    public static JDialog sayWaitDialog = new JDialog();
    static {
        sayWaitDialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        sayWaitDialog.setModal(true);
        sayWaitDialog.setTitle("Please Wait");
        JPanel jPanel1 = new JPanel();
        sayWaitDialog.setSize(new Dimension(255, 93));
        sayWaitDialog.getContentPane().setLayout(null);
        jPanel1.setBounds(new Rectangle(5, 5, 230, 45));
        jPanel1.setLayout(null);
        jPanel1.setBackground(new Color(255, 222, 214));
        JLabel jLabel1 = new JLabel();
        jLabel1.setText("Working.  Please wait!");
        jLabel1.setBounds(new Rectangle(5, 5, 220, 35));
        jLabel1.setHorizontalAlignment(SwingConstants.CENTER);
        jLabel1.setFont(new Font("Tahoma", 0, 16));
        jPanel1.add(jLabel1, null);
        sayWaitDialog.getContentPane().add(jPanel1, null);
        Login.center(sayWaitDialog);
    }
}
