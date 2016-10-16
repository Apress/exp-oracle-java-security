// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Supplement

package testojs.testa;

import java.awt.*;

import java.awt.event.*;

import java.awt.event.ActionEvent;

import javax.swing.*;
import javax.swing.JButton;
import javax.swing.JLabel;

import orajavsec.OracleJavaSecure;

public class TestAppA extends JFrame {
    private JPanel topMenuPanel = new JPanel();
    private JLabel userLabel = new JLabel();
    private JButton exitButton = new JButton();

    public static void main(String[] args) {
        new TestAppA();
    }

    public TestAppA() {
        try {
            jbInit();
            ojsInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void ojsInit() throws Exception {
    	new Login(this);
      userLabel.setText(OracleJavaSecure.getOSUserName());
        Login.center(this);
        this.setVisible(true);
    }

    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(512, 279));
        this.setTitle("Test Application A");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        topMenuPanel.setBounds(new Rectangle(5, 5, 480, 215));
        topMenuPanel.setLayout(null);
        topMenuPanel.setBackground(new Color(214, 255, 255));
        userLabel.setText("user");
        userLabel.setBounds(new Rectangle(25, 70, 425, 45));
        userLabel.setFont(new Font("Tahoma", 0, 24));
        userLabel.setHorizontalAlignment(SwingConstants.CENTER);
        exitButton.setText("Exit");
        exitButton.setBounds(new Rectangle(345, 160, 120, 40));
        exitButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    exitButton_actionPerformed(e);
                }
            });
        topMenuPanel.add(exitButton, null);
        topMenuPanel.add(userLabel, null);
        this.getContentPane().add(topMenuPanel, null);
    }

	private void this_windowClosing(WindowEvent e) {
        System.exit(0);
    }

    private void exitButton_actionPerformed(ActionEvent e) {
      this_windowClosing(null);
    }
}
