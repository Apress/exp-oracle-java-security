CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED APPSEC."orajavsec/Login" AS
// Copyright 2011, Dave Coffin

// From Chapter 12

package orajavsec;

import java.io.Serializable;

import orajavsec.RevLvlClassIntfc;

// Drop the "extends JDialog" from class definition
// It is unneeded and will be invalid on Oracle server
public class Login {
    public static class InnerRevLvlClass implements Serializable,
                                                     RevLvlClassIntfc {
        private static final long serialVersionUID = 2011010100L;
        private String innerClassRevLvl = "20110101a";

        public String getRevLvl() {
            return innerClassRevLvl;
        }
    }
}
/
