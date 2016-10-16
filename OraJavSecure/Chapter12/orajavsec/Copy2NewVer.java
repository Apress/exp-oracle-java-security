// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12

/*
 * Test by update innerClassRevLvl in TestOracleJavaSecure
 * also comment calls to putAppConnString() and putAppConnections()
 * then recompile TestOracleJavaSecure and run this to copy from previous version
 * then try running TestOracleJavaSecure with copied conn strings
 */

package orajavsec;

import java.awt.Color;
import java.awt.Dimension;

import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import javax.swing.SwingUtilities;

public class Copy2NewVer extends JFrame {
    JFrame thisComponent = this;
    static JFrame parent;
    // No local Connection - use appver connection for this application
    //static OracleConnection conn;

    private JPanel functionPanel = new JPanel();
    private JButton copyButton = new JButton();
    private JButton closeButton = new JButton();
    private JLabel jLabel1 = new JLabel();
    private JLabel jLabel3 = new JLabel();
    private JTextField prevVerTextField = new JTextField();
    private JLabel jLabel7 = new JLabel();
    private JLabel jLabel9 = new JLabel();
    private JLabel applicationIDLabel = new JLabel();
    private JLabel appClassLabel = new JLabel();

    public Copy2NewVer(JFrame parent) {
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

    public Copy2NewVer() {
        try {
            jbInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(769, 254));
        this.setTitle("Copy Connection Strings");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        functionPanel.setBounds(new Rectangle(5, 5, 730, 190));
        functionPanel.setLayout(null);
        functionPanel.setBackground(new Color(255, 247, 214));
        copyButton.setText("Copy Existing Conn Strings");
        copyButton.setBounds(new Rectangle(370, 140, 230, 30));
        copyButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    copyButton_actionPerformed(e);
                }
            });
        closeButton.setText("Close");
        closeButton.setBounds(new Rectangle(620, 140, 85, 30));
        closeButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    closeButton_actionPerformed(e);
                }
            });
        jLabel1.setText("Application Class:");
        jLabel1.setBounds(new Rectangle(220, 55, 115, 30));
        jLabel1.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel1.setFont(new Font("Tahoma", 0, 14));
        jLabel3.setText("Previous Version");
        jLabel3.setBounds(new Rectangle(120, 90, 150, 30));
        jLabel3.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel3.setFont(new Font("Tahoma", 0, 14));
        prevVerTextField.setBounds(new Rectangle(280, 90, 290, 30));
        jLabel7.setText("App ID:");
        jLabel7.setBounds(new Rectangle(10, 55, 75, 30));
        jLabel7.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel7.setFont(new Font("Tahoma", 0, 14));
        jLabel9.setText("Copy Existing Connection Strings for Application with This ID and Class");
        jLabel9.setBounds(new Rectangle(10, 10, 715, 40));
        jLabel9.setFont(new Font("Tahoma", 0, 16));
        jLabel9.setHorizontalAlignment(SwingConstants.CENTER);
        applicationIDLabel.setBounds(new Rectangle(90, 55, 140, 30));
        applicationIDLabel.setForeground(Color.blue);
        applicationIDLabel.setFont(new Font("Tahoma", 0, 14));
        appClassLabel.setBounds(new Rectangle(340, 55, 380, 30));
        appClassLabel.setFont(new Font("Tahoma", 0, 14));
        appClassLabel.setForeground(Color.blue);
        functionPanel.add(appClassLabel, null);
        functionPanel.add(applicationIDLabel, null);
        functionPanel.add(jLabel7, null);
        functionPanel.add(prevVerTextField, null);
        functionPanel.add(jLabel3, null);
        functionPanel.add(jLabel1, null);
        functionPanel.add(closeButton, null);
        functionPanel.add(copyButton, null);
        functionPanel.add(jLabel9, null);
        this.getContentPane().add(functionPanel, null);
    }

    private void this_windowClosing(WindowEvent e) {
        parent.setVisible(true);
        this.setVisible(false);
    }

    private void closeButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void copyButton_actionPerformed(ActionEvent e) {
        if (prevVerTextField.getText().equals("")) {
            JOptionPane.showMessageDialog(thisComponent,
                                          "Must specify previous version!");
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    OracleJavaSecure.copyAppConnections(prevVerTextField.getText());
                    Login.sayWaitDialog.setVisible(false);
                    prevVerTextField.setText("");
                }
            });
        // Ask the user to be patient while working
        Login.sayWaitDialog.setVisible(true);
    }

    private void dataInit() throws Exception {
        applicationIDLabel.setText(((OJSAdmin)parent).manageAppID);
        appClassLabel.setText(((OJSAdmin)parent).manageAppClass);
    }
}
