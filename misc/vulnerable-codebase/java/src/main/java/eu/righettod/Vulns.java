package eu.righettod;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.regex.Pattern;

public class Vulns {

    public static void realOne00(String name) throws Exception {
        //Real SQL Injection
        Connection connection = DriverManager.getConnection("x", "x", "");
        String sql = String.format("SELECT * FROM USERS WHERE LOGIN='%s'", name);
        try (Statement stmt1 = connection.createStatement()) {
            stmt1.executeUpdate(sql);
        }
    }

    public static void fakeOne00(String name) throws Exception {
        //Fake SQL Injection
        Connection connection = DriverManager.getConnection("x", "x", "");
        String new_name = name.replaceAll("'", "").replaceAll("-", "").replaceAll("\\", " ").trim();
        String sql = String.format("SELECT * FROM USERS WHERE LOGIN='%s'", new_name);
        try (Statement stmt2 = connection.createStatement()) {
            stmt2.executeUpdate(sql);
        }
    }

    public static void fakeOne01(String name) throws Exception {
        //Fake SQL Injection
        Connection connection = DriverManager.getConnection("x", "x", "");
        if (Pattern.matches("^[a-z]+$", name)) {
            String sql = String.format("SELECT * FROM USERS WHERE LOGIN='%s'", name);
            try (Statement stmt3 = connection.createStatement()) {
                stmt3.executeUpdate(sql);
            }
        }
    }
}
