// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12

package orajavsec;

import java.awt.*;
import java.awt.Rectangle;
import java.awt.event.*;

import java.awt.event.ActionEvent;

import javax.swing.*;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class OJSAdmin extends JFrame {
    String manageAppID = "";
    String manageAppClass = "";

    private JPanel topMenuPanel = new JPanel();
    private JButton addUserButton = new JButton();
    private JButton adminUserButton = new JButton();
    private JButton assignAppButton = new JButton();
    private JButton editConnStringsButton = new JButton();
    private JButton copyStringsButton = new JButton();
    private JButton exitButton = new JButton();
    private JButton registerNewAppButton = new JButton();
    private JLabel jLabel1 = new JLabel();
    private JLabel jLabel2 = new JLabel();
    private JLabel jLabel3 = new JLabel();
    private JLabel jLabel4 = new JLabel();
    private JLabel jLabel5 = new JLabel();
    private JLabel jLabel6 = new JLabel();
    private JPanel bottomMenuPanel = new JPanel();
    private JButton pickAppManageButton = new JButton();
    private JLabel jLabel7 = new JLabel();
    private JPanel jPanel1 = new JPanel();

    public static void main(String[] args) {
        // Put main() method right in this JFrame
        new OJSAdmin(args);
    }

    public OJSAdmin(String[] args) {
        try {
            jbInit();
            // Add extra init in separate method
            ojsInit(args);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void ojsInit(String[] args) throws Exception {
        // Method for initializing OJS functionality
        JPanel disablePanel = bottomMenuPanel;
        // Login does SSO, 2-Factor Auth and Application Authorization
        if (args.length < 2) {
            new Login(this);
            // Comment preceding line to bypass top menu, uncomment following lines
            //new Login(this, "HRVIEW", "testojs.TestOracleJavaSecure$AnyNameWeWant");
            //disablePanel = topMenuPanel;
        } else {
            // Call Login with alternate Application ID and Class name
            manageAppID = args[0];
            manageAppClass = args[1];
            new Login(this, manageAppID, manageAppClass);
            disablePanel = topMenuPanel;
        }
        // By default, we only use the top menu, so disable bottom components
        // When managing alternate application, we only use bottom menu
        Component[] comps = disablePanel.getComponents();
        for (int i = 0; i < comps.length; i++) {
            comps[i].setEnabled(false);
        }
        // This static utility method centers any component on the screen
        Login.center(this);
        // Finally, to see this frame, it must be made visible
        this.setVisible(true);
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(512, 415));
        this.setTitle("Oracle Java Secure Administration");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        topMenuPanel.setBounds(new Rectangle(5, 5, 480, 215));
        topMenuPanel.setLayout(null);
        topMenuPanel.setBackground(new Color(214, 255, 255));
        addUserButton.setText("Add / Modify User");
        addUserButton.setBounds(new Rectangle(25, 20, 185, 30));
        addUserButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    addUserButton_actionPerformed(e);
                }
            });
        adminUserButton.setText("Admin Users");
        adminUserButton.setBounds(new Rectangle(25, 60, 185, 30));
        adminUserButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    adminUserButton_actionPerformed(e);
                }
            });
        assignAppButton.setText("Assign Application");
        assignAppButton.setBounds(new Rectangle(25, 100, 185, 30));
        assignAppButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    assignAppButton_actionPerformed(e);
                }
            });
        editConnStringsButton.setText("Edit App Conn Strings");
        editConnStringsButton.setBounds(new Rectangle(25, 5, 185, 30));
        editConnStringsButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    editConnStringsButton_actionPerformed(e);
                }
            });
        copyStringsButton.setText("Copy to New Version");
        copyStringsButton.setBounds(new Rectangle(25, 45, 185, 30));
        copyStringsButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    copyStringsButton_actionPerformed(e);
                }
            });
        exitButton.setText("Exit");
        exitButton.setBounds(new Rectangle(350, 5, 85, 30));
        exitButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    exitButton_actionPerformed(e);
                }
            });
        registerNewAppButton.setText("Register New App");
        registerNewAppButton.setBounds(new Rectangle(25, 140, 185, 30));
        registerNewAppButton.setActionCommand("Register New App");
        registerNewAppButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    registerNewAppButton_actionPerformed(e);
                }
            });
        jLabel1.setText("Grant/Revoke Proxy for Admin");
        jLabel1.setBounds(new Rectangle(220, 60, 250, 30));
        jLabel2.setText("Add/Edit, Employee and User");
        jLabel2.setBounds(new Rectangle(220, 20, 250, 30));
        jLabel3.setText("Call with new Application Class");
        jLabel3.setBounds(new Rectangle(220, 140, 250, 30));
        jLabel4.setText("Grant/Revoke Proxy for Apps");
        jLabel4.setBounds(new Rectangle(220, 100, 250, 30));
        jLabel5.setText("Edit Conn Strings for App");
        jLabel5.setBounds(new Rectangle(220, 5, 250, 30));
        jLabel6.setText("Conn Strings from Prev Ver");
        jLabel6.setBounds(new Rectangle(220, 45, 250, 30));
        bottomMenuPanel.setBounds(new Rectangle(5, 225, 480, 90));
        bottomMenuPanel.setLayout(null);
        bottomMenuPanel.setBackground(new Color(215, 255, 255));
        pickAppManageButton.setText("Pick App To Manage");
        pickAppManageButton.setBounds(new Rectangle(25, 180, 185, 30));
        pickAppManageButton.setActionCommand("Register New App");
        pickAppManageButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    pickAppManageButton_actionPerformed(e);
                }
            });
        jLabel7.setText("Go to Bottom Menu Functions for Specific App");
        jLabel7.setBounds(new Rectangle(220, 180, 250, 30));
        jPanel1.setBounds(new Rectangle(5, 320, 480, 45));
        jPanel1.setLayout(null);
        jPanel1.setBackground(new Color(215, 255, 255));
        topMenuPanel.add(jLabel7, null);
        topMenuPanel.add(pickAppManageButton, null);
        topMenuPanel.add(jLabel4, null);
        topMenuPanel.add(jLabel3, null);
        topMenuPanel.add(jLabel2, null);
        topMenuPanel.add(jLabel1, null);
        topMenuPanel.add(registerNewAppButton, null);
        topMenuPanel.add(assignAppButton, null);
        topMenuPanel.add(adminUserButton, null);
        topMenuPanel.add(addUserButton, null);
        bottomMenuPanel.add(editConnStringsButton, null);
        bottomMenuPanel.add(jLabel5, null);
        bottomMenuPanel.add(copyStringsButton, null);
        bottomMenuPanel.add(jLabel6, null);
        jPanel1.add(exitButton, null);
        this.getContentPane().add(jPanel1, null);
        this.getContentPane().add(bottomMenuPanel, null);
        this.getContentPane().add(topMenuPanel, null);
    }

    private void addUserButton_actionPerformed(ActionEvent e) {
        new AddUser(this);
    }

    private void adminUserButton_actionPerformed(ActionEvent e) {
        new AdminUsers(this);
    }

    private void assignAppButton_actionPerformed(ActionEvent e) {
        new AssignApp(this);
    }

    private void editConnStringsButton_actionPerformed(ActionEvent e) {
        new EditAppConns(this);
    }

    private void copyStringsButton_actionPerformed(ActionEvent e) {
        new Copy2NewVer(this);
    }

    private void registerNewAppButton_actionPerformed(ActionEvent e) {
        new RegNewApp(this);
    }

    private void pickAppManageButton_actionPerformed(ActionEvent e) {
        new PickAppManage(this);
    }

    private void exitButton_actionPerformed(ActionEvent e) {
        System.exit(0);
    }

    private void this_windowClosing(WindowEvent e) {
        // Need to also kill the JVM when user clicks on window close [X] on frame
        System.exit(0);
    }
}
