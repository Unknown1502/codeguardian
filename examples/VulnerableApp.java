// Example: Vulnerable Java Web Application
// This file contains intentional vulnerabilities for testing CodeGuardian

import java.sql.*;
import java.io.*;
import java.security.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class VulnerableApp extends HttpServlet {
    
    // VULNERABILITY 1: Hardcoded Credentials
    private static final String DB_PASSWORD = "admin123";  // BAD: Hardcoded password
    private static final String API_KEY = "sk_live_51HxYZ123456789";  // BAD: Hardcoded API key
    private static final String ENCRYPTION_KEY = "MySecretKey123";  // BAD: Hardcoded encryption key
    
    
    // VULNERABILITY 2: SQL Injection
    public void getUserData(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", 
                "root", 
                DB_PASSWORD
            );
            
            // BAD: String concatenation in SQL query
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE id = " + userId;
            ResultSet rs = stmt.executeQuery(query);  // SQL Injection!
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            
            conn.close();
        } catch (SQLException e) {
            // VULNERABILITY: Information Disclosure
            e.printStackTrace();  // BAD: Stack trace exposed to user
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    
    // VULNERABILITY 3: Command Injection
    public void executeCommand(String userInput) throws IOException {
        // BAD: User input directly in command
        Runtime runtime = Runtime.getRuntime();
        String command = "ping -c 1 " + userInput;
        Process process = runtime.exec(command);  // Command Injection!
    }
    
    
    // VULNERABILITY 4: Path Traversal
    public void downloadFile(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String filename = request.getParameter("file");
        
        // BAD: No path validation
        String filePath = "/var/www/uploads/" + filename;
        // Attack: file=../../../../etc/passwd
        
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);  // Path Traversal!
        
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        fis.close();
    }
    
    
    // VULNERABILITY 5: XML External Entity (XXE)
    public void parseXML(String xmlData) throws Exception {
        // BAD: XXE not disabled
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        InputStream is = new ByteArrayInputStream(xmlData.getBytes());
        Document doc = builder.parse(is);  // XXE vulnerability!
    }
    
    
    // VULNERABILITY 6: Insecure Deserialization
    public Object deserializeObject(byte[] data) throws Exception {
        // BAD: Deserializing untrusted data
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();  // Insecure deserialization!
    }
    
    
    // VULNERABILITY 7: Weak Cryptography
    public String encryptPassword(String password) throws Exception {
        // BAD: MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    public String weakEncryption(String data) throws Exception {
        // BAD: DES is deprecated and insecure
        Cipher cipher = Cipher.getInstance("DES");
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    
    // VULNERABILITY 8: Insecure Random Number Generation
    public String generateToken() {
        // BAD: Random is not cryptographically secure
        Random random = new Random();
        return String.valueOf(random.nextInt());  // Predictable!
    }
    
    public String generateSessionId() {
        // BAD: Predictable session ID
        return String.valueOf(System.currentTimeMillis());
    }
    
    
    // VULNERABILITY 9: Missing Authentication
    public void deleteUser(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("id");
        
        // BAD: No authentication or authorization check
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/mydb", "root", DB_PASSWORD
        );
        
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("DELETE FROM users WHERE id = " + userId);
        conn.close();
    }
    
    
    // VULNERABILITY 10: LDAP Injection
    public void ldapSearch(String username) throws Exception {
        // BAD: User input directly in LDAP query
        String filter = "(uid=" + username + ")";  // LDAP Injection!
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        ctx.search("dc=example,dc=com", filter, new SearchControls());
    }
    
    
    // VULNERABILITY 11: Cross-Site Scripting (XSS)
    public void displayUserInput(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String userInput = request.getParameter("comment");
        
        // BAD: Unescaped user input in HTML
        response.setContentType("text/html");
        response.getWriter().println("<html><body>");
        response.getWriter().println("<h1>Your comment: " + userInput + "</h1>");  // XSS!
        response.getWriter().println("</body></html>");
    }
    
    
    // VULNERABILITY 12: SSRF (Server-Side Request Forgery)
    public String fetchURL(String url) throws Exception {
        // BAD: No URL validation
        URL targetUrl = new URL(url);  // SSRF vulnerability!
        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
        
        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream())
        );
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            response.append(line);
        }
        in.close();
        
        return response.toString();
    }
    
    
    // VULNERABILITY 13: Unvalidated Redirect
    public void redirect(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String url = request.getParameter("url");
        
        // BAD: No whitelist validation
        response.sendRedirect(url);  // Open redirect vulnerability!
    }
    
    
    // VULNERABILITY 14: Insecure File Permissions
    public void createFile(String filename) throws IOException {
        File file = new File(filename);
        
        // BAD: World-writable permissions
        file.setWritable(true, false);  // Insecure permissions!
        file.setReadable(true, false);
    }
    
    
    // VULNERABILITY 15: Race Condition
    private static int counter = 0;
    
    public void incrementCounter() {
        // BAD: No synchronization
        counter++;  // Race condition!
    }
    
    
    // VULNERABILITY 16: Memory Leak
    private static List<byte[]> leakyList = new ArrayList<>();
    
    public void allocateMemory() {
        // BAD: Never cleaned up
        leakyList.add(new byte[1024 * 1024]);  // Memory leak!
    }
    
    
    // VULNERABILITY 17: Trust Boundary Violation
    public void storeUserData(HttpServletRequest request) {
        String username = request.getParameter("username");
        
        // BAD: Storing untrusted data in session without validation
        HttpSession session = request.getSession();
        session.setAttribute("admin", username);  // Trust boundary violation!
    }
    
    
    // VULNERABILITY 18: Null Pointer Dereference
    public String processUser(User user) {
        // BAD: No null check
        return user.getName().toUpperCase();  // Possible NullPointerException!
    }
    
    
    // VULNERABILITY 19: Resource Leak
    public void readFile(String filename) throws IOException {
        // BAD: Stream not closed in finally block
        FileInputStream fis = new FileInputStream(filename);
        byte[] data = new byte[1024];
        fis.read(data);
        // Missing: fis.close() - Resource leak!
    }
    
    
    // VULNERABILITY 20: Unsafe Reflection
    public Object createInstance(String className) throws Exception {
        // BAD: User-controlled class instantiation
        Class<?> clazz = Class.forName(className);
        return clazz.newInstance();  // Arbitrary class instantiation!
    }
}


// Helper class
class User {
    private String name;
    
    public String getName() {
        return name;
    }
}
