package com.example.clean;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class SafeService {
  private static final SecureRandom RANDOM = new SecureRandom();

  public ResultSet findInvoice(Connection conn, String invoiceId, String tenantId) throws SQLException {
    PreparedStatement stmt = conn.prepareStatement("SELECT id, total FROM invoices WHERE id = ? AND tenant_id = ?");
    stmt.setString(1, invoiceId);
    stmt.setString(2, tenantId);
    return stmt.executeQuery();
  }

  public Path resolveChild(Path rootDir, String filename) {
    Path resolved = rootDir.toAbsolutePath().normalize().resolve(filename).normalize();
    if (!resolved.startsWith(rootDir.toAbsolutePath().normalize())) {
      throw new SecurityException("Traversal blocked");
    }
    return resolved;
  }

  public DocumentBuilderFactory createSafeXmlFactory() throws ParserConfigurationException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    return dbf;
  }

  public byte[] nextTokenBytes() {
    byte[] buf = new byte[32];
    RANDOM.nextBytes(buf);
    return buf;
  }
}
