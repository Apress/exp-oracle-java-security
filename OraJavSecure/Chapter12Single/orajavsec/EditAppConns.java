// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12

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

import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import javax.swing.SwingUtilities;

public class EditAppConns extends JFrame {
    JFrame thisComponent = this;
    static JFrame parent;
    // No local Connection - use appver connection for this application
    //static OracleConnection conn;

    private JPanel functionPanel = new JPanel();
    private JButton saveButton = new JButton();
    private JButton closeButton = new JButton();
    private JLabel jLabel1 = new JLabel();
    private JLabel jLabel2 = new JLabel();
    private JComboBox existingConnComboBox = new JComboBox();
    private JLabel jLabel3 = new JLabel();
    private JSeparator jSeparator1 = new JSeparator();
    private JLabel jLabel4 = new JLabel();
    private JLabel jLabel5 = new JLabel();
    private JLabel jLabel6 = new JLabel();
    private JLabel jLabel8 = new JLabel();
    private JTextField instanceTextField = new JTextField();
    private JTextField userTextField = new JTextField();
    private JTextField serverTextField = new JTextField();
    private JTextField portTextField = new JTextField();
    private JPasswordField passwordField = new JPasswordField();
    private JButton updateButton = new JButton();
    private JSeparator jSeparator2 = new JSeparator();
    private JSeparator jSeparator3 = new JSeparator();
    private JLabel jLabel7 = new JLabel();
    private JPanel jPanel1 = new JPanel();
    private JLabel jLabel9 = new JLabel();
    private JLabel connSuccessLabel = new JLabel();
    private JLabel applicationIDLabel = new JLabel();
    private JLabel appClassLabel = new JLabel();

    public EditAppConns(JFrame parent) {
        this();
        this.parent = parent;
        try {
            // need to have parent set before calling dataInit()
            dataInit();
            // Post jbInit visual setup
            Login.center(this);
            parent.setVisible(false);
            this.setVisible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public EditAppConns() {
        try {
            jbInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(769, 524));
        this.setTitle("Edit Application Connection Strings");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 45, 730, 420));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        saveButton.setText("Save List");
        saveButton.setBounds(new Rectangle(465, 375, 140, 30));
        saveButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    saveButton_actionPerformed(e);
                }
            });
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(625, 375, 85, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        jLabel1.setText("Application Class:");
        jLabel1.setBounds(new Rectangle(220, 15, 115, 30));
        jLabel1.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel1.setFont(new Font("Tahoma", 0, 14));
        jLabel2.setText("Existing Connections");
        jLabel2.setBounds(new Rectangle(15, 80, 150, 30));
        jLabel2.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel2.setFont(new Font("Tahoma", 0, 14));
        existingConnComboBox.setBounds(new Rectangle(170, 80, 410, 30));
        existingConnComboBox.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    existingConnComboBox_actionPerformed(e);
                }
            });
        jLabel3.setText("instance");
        jLabel3.setBounds(new Rectangle(15, 135, 150, 30));
        jLabel3.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel3.setFont(new Font("Tahoma", 0, 14));
        jSeparator1.setBounds(new Rectangle(60, 120, 595, 10));
        jLabel4.setText("password");
        jLabel4.setBounds(new Rectangle(15, 205, 150, 30));
        jLabel4.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel4.setFont(new Font("Tahoma", 0, 14));
        jLabel5.setText("server");
        jLabel5.setBounds(new Rectangle(15, 240, 150, 30));
        jLabel5.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel5.setFont(new Font("Tahoma", 0, 14));
        jLabel6.setText("port");
        jLabel6.setBounds(new Rectangle(15, 275, 150, 30));
        jLabel6.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel6.setFont(new Font("Tahoma", 0, 14));
        jLabel8.setText("user");
        jLabel8.setBounds(new Rectangle(15, 170, 150, 30));
        jLabel8.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel8.setFont(new Font("Tahoma", 0, 14));
        instanceTextField.setBounds(new Rectangle(175, 135, 290, 30));
        instanceTextField.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    instanceTextField_keyReleased(e);
                }
            });
        userTextField.setBounds(new Rectangle(175, 170, 290, 30));
        userTextField.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    userTextField_keyReleased(e);
                }
            });
        serverTextField.setBounds(new Rectangle(175, 240, 290, 30));
        serverTextField.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    serverTextField_keyReleased(e);
                }
            });
        portTextField.setBounds(new Rectangle(175, 275, 290, 30));
        portTextField.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    portTextField_keyReleased(e);
                }
            });
        passwordField.setBounds(new Rectangle(175, 205, 290, 30));
        passwordField.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    passwordField_keyReleased(e);
                }
            });
        updateButton.setText("Update Connection String");
        updateButton.setBounds(new Rectangle(480, 205, 230, 30));
        updateButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    updateButton_actionPerformed(e);
                }
            });
        jSeparator2.setBounds(new Rectangle(65, 360, 595, 10));
        jSeparator3.setBounds(new Rectangle(60, 60, 595, 10));
        jLabel7.setText("App ID:");
        jLabel7.setBounds(new Rectangle(10, 15, 75, 30));
        jLabel7.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel7.setFont(new Font("Tahoma", 0, 14));
        jPanel1.setBounds(new Rectangle(5, 5, 730, 40));
        jPanel1.setBackground(new Color(255, 247, 214));
        jPanel1.setLayout(null);
        jLabel9.setText("Managing Application with This ID and Class");
        jLabel9.setBounds(new Rectangle(5, 5, 715, 40));
        jLabel9.setFont(new Font("Tahoma", 0, 16));
        jLabel9.setHorizontalAlignment(SwingConstants.CENTER);
        connSuccessLabel.setBounds(new Rectangle(175, 315, 540, 35));
        connSuccessLabel.setFont(new Font("Tahoma", 0, 14));
        connSuccessLabel.setForeground(Color.blue);
        applicationIDLabel.setBounds(new Rectangle(90, 15, 140, 30));
        applicationIDLabel.setForeground(Color.blue);
        applicationIDLabel.setFont(new Font("Tahoma", 0, 14));
        appClassLabel.setBounds(new Rectangle(340, 15, 380, 30));
        appClassLabel.setFont(new Font("Tahoma", 0, 14));
        appClassLabel.setForeground(Color.blue);
        functionPanel.add(appClassLabel, null);
        functionPanel.add(applicationIDLabel, null);
        functionPanel.add(connSuccessLabel, null);
        functionPanel.add(jLabel7, null);
        functionPanel.add(jSeparator3, null);
        functionPanel.add(jSeparator2, null);
        functionPanel.add(updateButton, null);
        functionPanel.add(passwordField, null);
        functionPanel.add(portTextField, null);
        functionPanel.add(serverTextField, null);
        functionPanel.add(userTextField, null);
        functionPanel.add(instanceTextField, null);
        functionPanel.add(jLabel8, null);
        functionPanel.add(jLabel6, null);
        functionPanel.add(jLabel5, null);
        functionPanel.add(jLabel4, null);
        functionPanel.add(jSeparator1, null);
        functionPanel.add(jLabel3, null);
        functionPanel.add(existingConnComboBox, null);
        functionPanel.add(jLabel2, null);
        functionPanel.add(jLabel1, null);
        functionPanel.add(closeButton, null);
        functionPanel.add(saveButton, null);
        jPanel1.add(jLabel9, null);
        this.getContentPane().add(jPanel1, null);
        this.getContentPane().add(functionPanel, null);
    }

    private void this_windowClosing(WindowEvent e) {
        parent.setVisible(true);
        this.setVisible(false);
    }

    private void closeButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void blankAll() {
        connSuccessLabel.setText("");
        instanceTextField.setText("");
        userTextField.setText("");
        passwordField.setText("");
        serverTextField.setText("");
        portTextField.setText("");
    }

    private void updateButton_actionPerformed(ActionEvent e) {
        if (instanceTextField.getText().equals("") ||
            userTextField.getText().equals("") ||
            passwordField.getPassword().length == 0 ||
            serverTextField.getText().equals("") ||
            portTextField.getText().equals("")) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Must have values for All Fields!");
            return;
        }
        connSuccessLabel.setText(OracleJavaSecure.putAppConnString(instanceTextField.getText().toUpperCase(),
                                                                   userTextField.getText().toUpperCase(),
                                                                   new String(passwordField.getPassword()),
                                                                   serverTextField.getText(),
                                                                   portTextField.getText(),
                                                                   true));
        // Add any new connection strings to existingConnComboBox
        Vector<String> connList = OracleJavaSecure.listConnNames();
        boolean found;
        for (String connName : connList) {
            found = false;
            for (int i = 0; i < existingConnComboBox.getItemCount(); i++) {
                if (existingConnComboBox.getItemAt(i).equals(connName)) {
                    found = true;
                    break;
                }
            }
            if (!found)
                existingConnComboBox.addItem(connName);
        }
    }

    private void existingConnComboBox_actionPerformed(ActionEvent e) {
        connSuccessLabel.setText("");
        if (existingConnComboBox.getSelectedIndex() == 0)
            return;
        String connName = (String)existingConnComboBox.getSelectedItem();
        blankAll();
        int place = connName.indexOf("/");
        instanceTextField.setText(connName.substring(0, place));
        userTextField.setText(connName.substring(place + 1));
    }

    private void saveButton_actionPerformed(ActionEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    // Here, I am oracle user proxying through appver with only create_session_role
                    // So cannot see the appsec_admin_pkg unless unless have role appver_conns on apver
                    OracleJavaSecure.putAppConnections();
                    Login.sayWaitDialog.setVisible(false);
                }
            });
        // Ask the user to be patient while working
        Login.sayWaitDialog.setVisible(true);
    }

    private void dataInit() throws Exception {
        applicationIDLabel.setText(((OJSAdmin)parent).manageAppID);
        appClassLabel.setText(((OJSAdmin)parent).manageAppClass);
        connSuccessLabel.setText("");
        Vector<String> connList = OracleJavaSecure.listConnNames();
        // This throws event to run existingEmpComboBox_actionPerformed() method
        // Calls blankAll()
        existingConnComboBox.removeAllItems();
        existingConnComboBox.addItem("");
        for (String connName : connList)
            existingConnComboBox.addItem(connName);
    }

    private void instanceTextField_keyReleased(KeyEvent e) {
        connSuccessLabel.setText("");
    }

    private void userTextField_keyReleased(KeyEvent e) {
        connSuccessLabel.setText("");
    }

    private void passwordField_keyReleased(KeyEvent e) {
        connSuccessLabel.setText("");
    }

    private void serverTextField_keyReleased(KeyEvent e) {
        connSuccessLabel.setText("");
    }

    private void portTextField_keyReleased(KeyEvent e) {
        connSuccessLabel.setText("");
    }
}
