<?php
// Example: Vulnerable PHP Web Application
// This file contains intentional vulnerabilities for testing CodeGuardian


// VULNERABILITY 1: Hardcoded Credentials
$db_password = "MySecretPassword123";  // BAD: Hardcoded password
$api_key = "sk_live_abc123xyz789";  // BAD: Hardcoded API key
define('SECRET_KEY', 'super_secret_encryption_key');  // BAD: Hardcoded secret


// VULNERABILITY 2: SQL Injection
function getUserById($user_id) {
    global $db_password;
    
    $conn = mysqli_connect("localhost", "root", $db_password, "mydb");
    
    // BAD: Direct variable interpolation in SQL
    $query = "SELECT * FROM users WHERE id = $user_id";
    $result = mysqli_query($conn, $query);  // SQL Injection!
    
    if ($row = mysqli_fetch_assoc($result)) {
        return $row;
    }
    
    mysqli_close($conn);
}


// VULNERABILITY 3: Cross-Site Scripting (XSS)
function displayComment() {
    $comment = $_GET['comment'];
    
    // BAD: Unescaped user input in HTML
    echo "<div class='comment'>" . $comment . "</div>";  // XSS vulnerability!
}


// VULNERABILITY 4: Command Injection
function pingHost() {
    $host = $_POST['hostname'];
    
    // BAD: User input in shell command
    $output = shell_exec("ping -c 1 " . $host);  // Command Injection!
    echo "<pre>$output</pre>";
}


// VULNERABILITY 5: Path Traversal
function downloadFile() {
    $filename = $_GET['file'];
    
    // BAD: No path validation
    $filepath = "/var/www/uploads/" . $filename;
    // Attack: file=../../../../etc/passwd
    
    if (file_exists($filepath)) {
        readfile($filepath);  // Path Traversal!
    }
}


// VULNERABILITY 6: Remote Code Execution
function evaluateExpression() {
    $expr = $_POST['expression'];
    
    // BAD: eval() with user input
    $result = eval("return " . $expr . ";");  // Arbitrary code execution!
    echo "Result: $result";
}


// VULNERABILITY 7: File Inclusion
function loadTemplate() {
    $template = $_GET['template'];
    
    // BAD: User-controlled file inclusion
    include("/templates/" . $template . ".php");  // LFI/RFI vulnerability!
}


// VULNERABILITY 8: Insecure Deserialization
function loadUserData() {
    $data = $_POST['user_data'];
    
    // BAD: Unserializing untrusted data
    $user = unserialize($data);  // Insecure deserialization!
    return $user;
}


// VULNERABILITY 9: Weak Cryptography
function hashPassword($password) {
    // BAD: MD5 is cryptographically broken
    return md5($password);  // Weak hashing!
}

function encryptData($data) {
    // BAD: Weak encryption algorithm
    $iv = '1234567890123456';  // BAD: Static IV
    $encrypted = openssl_encrypt($data, 'des-cbc', SECRET_KEY, 0, $iv);
    return $encrypted;
}


// VULNERABILITY 10: Session Fixation
function loginUser() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Authenticate user...
    
    // BAD: Not regenerating session ID after login
    $_SESSION['user'] = $username;  // Session fixation!
    $_SESSION['admin'] = true;
}


// VULNERABILITY 11: CSRF (No CSRF Token)
function deleteAccount() {
    $user_id = $_POST['user_id'];
    
    // BAD: No CSRF token validation
    $conn = mysqli_connect("localhost", "root", $db_password, "mydb");
    mysqli_query($conn, "DELETE FROM users WHERE id = $user_id");  // CSRF vulnerability!
    mysqli_close($conn);
}


// VULNERABILITY 12: XML External Entity (XXE)
function parseXML() {
    $xml_data = file_get_contents('php://input');
    
    // BAD: XXE not disabled
    $xml = simplexml_load_string($xml_data);  // XXE vulnerability!
    return $xml;
}


// VULNERABILITY 13: Information Disclosure
function showError($error) {
    // BAD: Exposing sensitive error information
    echo "Error: " . $error->getMessage();
    echo "\n" . $error->getTraceAsString();  // Stack trace exposed!
    
    // BAD: Exposing phpinfo
    if ($_GET['debug'] == '1') {
        phpinfo();  // Information disclosure!
    }
}


// VULNERABILITY 14: Missing Authentication
function adminDeleteUser() {
    // BAD: No authentication check
    $user_id = $_GET['id'];
    
    $conn = mysqli_connect("localhost", "root", $db_password, "mydb");
    mysqli_query($conn, "DELETE FROM users WHERE id = $user_id");
    mysqli_close($conn);
    
    echo "User deleted";
}


// VULNERABILITY 15: Insecure File Upload
function uploadFile() {
    $target_dir = "/var/www/uploads/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    
    // BAD: No file type or size validation
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "File uploaded successfully";  // Malicious file upload!
    }
}


// VULNERABILITY 16: LDAP Injection
function ldapAuth($username, $password) {
    $ldap_conn = ldap_connect("ldap://localhost:389");
    
    // BAD: User input directly in LDAP filter
    $filter = "(uid=" . $username . ")";  // LDAP Injection!
    $search = ldap_search($ldap_conn, "dc=example,dc=com", $filter);
    
    return ldap_get_entries($ldap_conn, $search);
}


// VULNERABILITY 17: Open Redirect
function redirect() {
    $url = $_GET['url'];
    
    // BAD: No whitelist validation
    header("Location: " . $url);  // Open redirect!
    exit();
}


// VULNERABILITY 18: Server-Side Request Forgery (SSRF)
function fetchURL() {
    $url = $_POST['url'];
    
    // BAD: No URL validation
    $content = file_get_contents($url);  // SSRF vulnerability!
    echo $content;
}


// VULNERABILITY 19: Race Condition (TOCTOU)
function processFile($filename) {
    // Time-of-check
    if (file_exists($filename)) {
        // BAD: Time gap between check and use
        sleep(1);
        
        // Time-of-use
        $content = file_get_contents($filename);  // TOCTOU race condition!
        return $content;
    }
}


// VULNERABILITY 20: Insecure Direct Object Reference (IDOR)
function viewUserProfile() {
    $user_id = $_GET['id'];
    
    // BAD: No authorization check
    $conn = mysqli_connect("localhost", "root", $db_password, "mydb");
    $query = "SELECT * FROM user_profiles WHERE user_id = " . intval($user_id);
    $result = mysqli_query($conn, $query);  // IDOR vulnerability!
    
    if ($row = mysqli_fetch_assoc($result)) {
        echo json_encode($row);  // May expose other users' data!
    }
    
    mysqli_close($conn);
}


// VULNERABILITY 21: Type Juggling
function authenticate() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $conn = mysqli_connect("localhost", "root", $db_password, "mydb");
    $query = "SELECT password FROM users WHERE username = '" . 
             mysqli_real_escape_string($conn, $username) . "'";
    $result = mysqli_query($conn, $query);
    
    if ($row = mysqli_fetch_assoc($result)) {
        // BAD: Type juggling vulnerability
        if ($row['password'] == $password) {  // Use === instead!
            return true;
        }
    }
    
    return false;
}


// VULNERABILITY 22: Mass Assignment
function updateUserProfile() {
    $user_id = $_SESSION['user_id'];
    
    // BAD: No whitelist of allowed fields
    $conn = mysqli_connect("localhost", "root", $db_password, "mydb");
    
    $fields = [];
    foreach ($_POST as $key => $value) {
        // Attacker could inject: is_admin=1
        $fields[] = "$key = '" . mysqli_real_escape_string($conn, $value) . "'";
    }
    
    $query = "UPDATE users SET " . implode(", ", $fields) . " WHERE id = $user_id";
    mysqli_query($conn, $query);  // Mass assignment!
    
    mysqli_close($conn);
}


// VULNERABILITY 23: Insecure Randomness
function generateToken() {
    // BAD: rand() is not cryptographically secure
    return md5(rand());  // Predictable token!
}


// VULNERABILITY 24: Header Injection
function setCustomHeader() {
    $name = $_GET['name'];
    
    // BAD: User input in header
    header("X-Custom-Name: " . $name);  // Header injection!
}


// BAD: Error reporting enabled in production
error_reporting(E_ALL);
ini_set('display_errors', 1);  // Information disclosure!

// BAD: Register globals (if enabled)
foreach ($_GET as $key => $value) {
    $$key = $value;  // Variable variable vulnerability!
}

?>
