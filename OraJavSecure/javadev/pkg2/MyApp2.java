/*
 * javadev/pkg2/MyApp2.java
 * Copyright 2011, David Coffin
 */
package pkg2;
import oracle.sql.ARRAY;
import mypkg.MyRef;
public class MyApp2 {
    private ARRAY myArray = null;
    static MyRef myRef;
    public static void main( String[] args ) {
        MyApp2 m = new MyApp2();
        MyRef useRef = new MyRef();
        m.setRef( useRef );
        ARRAY mA = m.getArray();
        myRef = new MyRef();
    }
    public ARRAY getArray() {
        return myArray;
    }
    void setRef( MyRef useRef ) {
        myRef = useRef;
    }
}
