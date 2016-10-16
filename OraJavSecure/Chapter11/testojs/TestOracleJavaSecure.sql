CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED APPSEC."testojs/TestOracleJavaSecure" AS
// Copyright 2011, Dave Coffin

// From Chapter 11

package testojs;

import java.io.Serializable;

import orajavsec.RevLvlClassIntfc;

public class TestOracleJavaSecure {
    public static class AnyNameWeWant
        implements Serializable, RevLvlClassIntfc
    {
        private static final long serialVersionUID = 2011013100L;
        private String innerClassRevLvl = "20110131a";
        public String getRevLvl() {
            return innerClassRevLvl;
        }
    }
}