package com.example.vuln;

import java.io.File;
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class VulnService {
    public void unsafeQuery(Connection conn, HttpServletRequest req) throws Exception {
        String user = req.getParameter("user");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM accounts WHERE username = '" + user + "'");
    }

    public void unsafeExec(HttpServletRequest req) throws Exception {
        String host = req.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public boolean badPathCheck(File baseDir, File targetFile) throws Exception {
        return targetFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath());
    }
}
