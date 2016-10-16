// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Supplement

// Skipping update of fields that are foreign keyed, types or calculated

package com.org.oeview;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;

import java.awt.GridLayout;
import java.awt.Rectangle;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;

import java.awt.event.WindowEvent;

import java.sql.Statement;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class OEViewDialog extends JDialog {
    OEView parent;

    private JPanel jPanel1 = new JPanel();
    private GridLayout gridLayout1 = new GridLayout(17, 2);
    private JLabel jLabel1 = new JLabel();
    private JTextField jTextField1 = new JTextField();
    private JLabel jLabel2 = new JLabel();
    private JTextField jTextField2 = new JTextField();
    private JLabel jLabel3 = new JLabel();
    private JTextField jTextField3 = new JTextField();
    private JLabel jLabel4 = new JLabel();
    private JTextField jTextField4 = new JTextField();
    private JLabel jLabel5 = new JLabel();
    private JTextField jTextField5 = new JTextField();
    private JLabel jLabel6 = new JLabel();
    private JTextField jTextField6 = new JTextField();
    private JLabel jLabel7 = new JLabel();
    private JTextField jTextField7 = new JTextField();
    private JLabel jLabel8 = new JLabel();
    private JTextField jTextField8 = new JTextField();
    private JLabel jLabel9 = new JLabel();
    private JTextField jTextField9 = new JTextField();
    private JLabel jLabel10 = new JLabel();
    private JTextField jTextField10 = new JTextField();
    private JLabel jLabel11 = new JLabel();
    private JTextField jTextField11 = new JTextField();
    private JLabel jLabel12 = new JLabel();
    private JTextField jTextField12 = new JTextField();
    private JLabel jLabel13 = new JLabel();
    private JTextField jTextField13 = new JTextField();
    private JLabel jLabel14 = new JLabel();
    private JTextField jTextField14 = new JTextField();
    private JLabel jLabel15 = new JLabel();
    private JTextField jTextField15 = new JTextField();
    private JLabel jLabel16 = new JLabel();
    private JLabel jLabel17 = new JLabel();
    private JButton cancelButton = new JButton();
    private JButton saveButton = new JButton();

    public OEViewDialog() {
        this(null, "", false);
    }

    public OEViewDialog(Frame parent, String title, boolean modal) {
        super(parent, title, modal);
        try {
            jbInit();
            this.setVisible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.setSize(new Dimension(563, 487));
        this.getContentPane().setLayout(null);
        this.setTitle("OE Customer Details");
        this.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    this_windowClosing(e);
                }
            });
        jPanel1.setBounds(new Rectangle(10, 5, 520, 430));
        jPanel1.setBackground(new Color(214, 255, 255));
        jPanel1.setLayout(gridLayout1);
        jPanel1.add(jLabel1, null);
        jPanel1.add(jTextField1, null);
        jPanel1.add(jLabel2, null);
        jPanel1.add(jTextField2, null);
        jPanel1.add(jLabel3, null);
        jPanel1.add(jTextField3, null);
        jPanel1.add(jLabel4, null);
        jPanel1.add(jTextField4, null);
        jPanel1.add(jLabel5, null);
        jPanel1.add(jTextField5, null);
        jPanel1.add(jLabel6, null);
        jPanel1.add(jTextField6, null);
        jPanel1.add(jLabel7, null);
        jPanel1.add(jTextField7, null);
        jPanel1.add(jLabel8, null);
        jPanel1.add(jTextField8, null);
        jPanel1.add(jLabel9, null);
        jPanel1.add(jTextField9, null);
        jPanel1.add(jLabel10, null);
        jPanel1.add(jTextField10, null);
        jPanel1.add(jLabel11, null);
        jPanel1.add(jTextField11, null);
        jPanel1.add(jLabel12, null);
        jPanel1.add(jTextField12, null);
        jPanel1.add(jLabel13, null);
        jPanel1.add(jTextField13, null);
        jPanel1.add(jLabel14, null);
        jPanel1.add(jTextField14, null);
        jPanel1.add(jLabel15, null);
        jPanel1.add(jTextField15, null);
        jPanel1.add(jLabel16, null);
        jPanel1.add(jLabel17, null);
        jPanel1.add(cancelButton, null);
        jPanel1.add(saveButton, null);
        this.getContentPane().add(jPanel1, null);
        jLabel1.setText("CUSTOMER_ID");
        jLabel2.setText("CUST_FIRST_NAME");
        jLabel3.setText("CUST_LAST_NAME");
        jLabel4.setText("CUST_ADDRESS");
        jLabel5.setText("PHONE_NUMBERS");
        jLabel6.setText("NLS_LANGUAGE");
        jLabel7.setText("NLS_TERRITORY");
        jLabel8.setText("CREDIT_LIMIT");
        jLabel9.setText("CUST_EMAIL");
        jLabel10.setText("ACCOUNT_MGR_ID");
        jLabel11.setText("CUST_GEO_LOCATION");
        jLabel12.setText("DATE_OF_BIRTH");
        jLabel13.setText("MARITAL_STATUS");
        jLabel14.setText("GENDER");
        jLabel15.setText("INCOME_LEVEL");
        jLabel16.setText("");
        jLabel17.setText("");
        jLabel1.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel1.setForeground(Color.darkGray);
        jLabel2.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel3.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel4.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel4.setForeground(Color.darkGray);
        jLabel5.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel5.setForeground(Color.darkGray);
        jLabel6.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel6.setForeground(Color.darkGray);
        jLabel7.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel7.setForeground(Color.darkGray);
        jLabel8.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel9.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel10.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel10.setForeground(Color.darkGray);
        jLabel11.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel11.setForeground(Color.darkGray);
        jLabel12.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel13.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel14.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel15.setHorizontalAlignment(SwingConstants.RIGHT);
        jLabel15.setForeground(Color.darkGray);
        jTextField1.setEnabled(false);
        jTextField4.setEnabled(false);
        jTextField5.setEnabled(false);
        jTextField6.setEnabled(false);
        jTextField7.setEnabled(false);
        jTextField10.setEnabled(false);
        jTextField11.setEnabled(false);
        jTextField15.setEnabled(false);
        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    cancelButton_actionPerformed(e);
                }
            });
        saveButton.setText("Save");
        saveButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    saveButton_actionPerformed(e);
                }
            });
    }

    void setValues(OEView parent) {
        this.parent = parent;
        parent.setVisible(false);
        jTextField1.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  0));
        jTextField2.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  1));
        jTextField3.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  2));
        jTextField4.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  3));
        jTextField5.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  4));
        jTextField6.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  5));
        jTextField7.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  6));
        jTextField8.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  7));
        jTextField9.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                  8));
        jTextField10.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                   9));
        jTextField11.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                   10));
        jTextField12.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                   11));
        jTextField13.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                   12));
        jTextField14.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                   13));
        jTextField15.setText((String)parent.oeViewTable.getValueAt(parent.oeViewTable.getSelectedRow(),
                                                                   14));
    }

    private void this_windowClosing(WindowEvent e) {
        parent.setVisible(true);
        parent.dataInit();
        this.dispose();
    }

    private void cancelButton_actionPerformed(ActionEvent e) {
        this_windowClosing(null);
    }

    private void saveButton_actionPerformed(ActionEvent e) {
        Statement stmt = null;
        int count;
        try {
            stmt = parent.conn.createStatement();
            count =
                    stmt.executeUpdate("update OE.customers set CUST_FIRST_NAME='" +
                                       jTextField2.getText() +
                                       "', CUST_LAST_NAME='" +
                                       jTextField3.getText() +
                                       /*
                                       "', CUST_ADDRESS='" +
                                       jTextField4.getText() +
                                       "', PHONE_NUMBERS='" +
                                       jTextField5.getText() +
                                       "', NLS_LANGUAGE='" +
                                       jTextField6.getText() +
                                       "', NLS_TERRITORY='" +
                                       jTextField7.getText() +
                                       */
                                       "', CREDIT_LIMIT='" + jTextField8.getText() +
                                       "', CUST_EMAIL='" + jTextField9.getText() +
                                       /*
                                       "', ACCOUNT_MGR_ID='" +
                                       jTextField10.getText() +
                                       "', CUST_GEO_LOCATION='" +
                                       jTextField11.getText() +
                                       */
                                       "', DATE_OF_BIRTH=to_date('" + 
                                       jTextField12.getText() +
                                       "', 'MM/DD/YYYY' ), MARITAL_STATUS='" +
                                       jTextField13.getText() + "', GENDER='" +
                                       jTextField14.getText() +
                                       /*
                                       "', INCOME_LEVEL='" +
                                       jTextField15.getText() +
                                       */
                                       "' where CUSTOMER_ID='" + 
                                       jTextField1.getText() + "'");
            if (count == 0) {
                // At present, only updating existing records, otherwise, implement this
                stmt.executeUpdate("insert into OE.customers " +
                                   "( CUSTOMER_ID, CUST_FIRST_NAME, CUST_LAST_NAME, CUST_ADDRESS, " +
                                   "PHONE_NUMBERS, NLS_LANGUAGE, NLS_TERRITORY, CREDIT_LIMIT, CUST_EMAIL, " +
                                   "ACCOUNT_MGR_ID, CUST_GEO_LOCATION, DATE_OF_BIRTH, MARITAL_STATUS, " +
                                   "GENDER, INCOME_LEVEL ) values ( " +
                                   jTextField1.getText() + ", " +
                                   jTextField2.getText() + ", " +
                                   jTextField3.getText() + ", " +
                                   jTextField4.getText() + ", " +
                                   jTextField5.getText() + ", " +
                                   jTextField6.getText() + ", " +
                                   jTextField7.getText() + ", " +
                                   jTextField8.getText() + ", " +
                                   jTextField9.getText() + ", " +
                                   jTextField10.getText() + ", " +
                                   jTextField11.getText() + ", " +
                                   jTextField12.getText() + ", " +
                                   jTextField13.getText() + ", " +
                                   jTextField14.getText() + ", " +
                                   jTextField15.getText() + ")");
            }
        } catch (Exception x) {
            x.printStackTrace();
            JOptionPane.showMessageDialog(this, x.toString());
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (Exception y) {
            }
        }
        this_windowClosing(null);
    }
}
