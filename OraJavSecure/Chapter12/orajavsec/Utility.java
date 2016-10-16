// Copyright 2011, Dave Coffin
// Use JDK 1.5 or later and have Oracle ojdbc5.jar or later on client classpath

// From Chapter 12

package orajavsec;

public class Utility {

    private Utility() {
        // A private constructor keeps everyone from instantiating this class
        // All methods and members are static
    }

    static String pullIDFromParens(String inValue) {
        String rtrnValue = "";
        try {
            int openPlace = inValue.indexOf("(");
            int closePlace = inValue.indexOf(")", openPlace);
            if (openPlace > -1 && closePlace > -1)
                rtrnValue = inValue.substring(openPlace + 1, closePlace);
        } catch (Exception x) {
        }
        return rtrnValue;
    }
}
