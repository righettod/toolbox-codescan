# README

![Update the SemGrep scan reports of sandboxes codebase](https://github.com/righettod/toolbox-codescan/actions/workflows/update_sandbox_semgrep_scan_reports.yml/badge.svg?branch=main)

## Description

🔬 Tests and POC for the implementation of this [idea](https://github.com/righettod/toolbox-codescan/issues/2).

🐞 The sample test application with vulnerabilites was taken from this [project](https://github.com/appsecco/dvja).

📦 File [cwec_v4.17.xml](cwec_v4.17.xml) come from [here](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip).

## Execution steps of the POC

1. Start the Ollama model:

```shell
ollama pull qwen2.5-coder:latest
ollama run qwen2.5-coder:latest
```

2. Run the script [poc.py](poc.py).

## Obervations

### Remark 01

🤔 Giving the full source code can lead the model to bad response. Indeed, in the following source code, SemGrep found 2 SQLI:

```java
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
        if(Pattern.matches("[a-z]+",name)){
            String sql = String.format("SELECT * FROM USERS WHERE LOGIN='%s'", name);
            try (Statement stmt = connection.createStatement()) {
                stmt.executeUpdate(sql);
            }
        }
    }
}
```

When asking if the SQLI found in method `fakeOne00` was really existing, the model replied this:

```json
{
  "present": "Yes",
  "explanation": "The vulnerability is present in the `realOne00` method, starting from line 25 in column 17 and ending on line 25 in column 40. The SQL query is constructed using the `String.format` method with user-provided input (`name`). This directly leads to a SQL injection vulnerability because the input is not properly sanitized. The `fakeOne00` method attempts to mitigate this by checking if the input contains only lowercase letters, but it does not address other potential issues and thus does not fully fix the vulnerability."
}
```

Line 25 in the code is refering to statement in the method `fakeOne00` and not `realOne00`. The model identified some validation on the method `fakeOne00` but consider thant the SQLI still exists.

This not false to consider this as indeed there is a SQLI but hard to exploit as there is no allowed character allowing to alter the query.

If I add the following instruction to the system prompt to clarify the case of SQLI `If the vulnerability in an sql injection one then you must only consider the vulnerability really present if it is possible to change the original sql query.` then the model replied this:

```json
{
  "present": "Yes",
  "explanation": "The vulnerability is present because the SQL query in the 'realOne00' method uses a formatted string to construct the SQL command, which can lead to SQL injection if the user input (in this case 'name') is not properly sanitized. The use of java.sql.Statement instead of java.sql.PreparedStatement allows for direct execution of the SQL string with no protection against SQL injection attacks."
}
```

## References used

* <https://ollama.com/library/qwen2.5-coder>
* <https://github.com/appsecco/dvja>
* <https://cwe.mitre.org/data/xml/cwec_latest.xml.zip>
