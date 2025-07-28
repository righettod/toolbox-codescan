package eu.righettod;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class Vulns {

    public static void realOne00(String name) throws Exception {
        //Real SQL Injection
        Connection connection = DriverManager.getConnection("x", "x", "");
        String sql = String.format("SELECT * FROM USERS WHERE LOGIN='%s'", name);
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }

    public static void fakeOne00(String name) throws Exception {
        //Fake SQL Injection
        Connection connection = DriverManager.getConnection("x", "x", "");
        String new_name = name.replaceAll("'", "").replaceAll("-", "").replace('\\',' ').trim();
        String sql = String.format("SELECT * FROM USERS WHERE LOGIN='%s'", new_name);
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }
}
