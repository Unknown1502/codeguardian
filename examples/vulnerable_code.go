// Example: Vulnerable Go Web Application
// This file contains intentional vulnerabilities for testing CodeGuardian

package main

import (
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"
)


// VULNERABILITY 1: Hardcoded Credentials
const (
	DBPassword    = "MySecretPassword123"  // BAD: Hardcoded password
	APIKey        = "sk_live_abc123xyz789" // BAD: Hardcoded API key
	JWTSecret     = "my_super_secret_jwt_key_12345"  // BAD: Hardcoded secret
	AWSAccessKey  = "AKIAIOSFODNN7EXAMPLE"  // BAD: Hardcoded AWS key
)


// VULNERABILITY 2: SQL Injection
func getUserByID(userID string) (string, error) {
	db, err := sql.Open("mysql", "root:"+DBPassword+"@tcp(localhost:3306)/mydb")
	if err != nil {
		return "", err
	}
	defer db.Close()

	// BAD: String concatenation in SQL query
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
	rows, err := db.Query(query)  // SQL Injection!
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var result string
	if rows.Next() {
		rows.Scan(&result)
	}
	return result, nil
}


// VULNERABILITY 3: Command Injection
func pingHost(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")

	// BAD: User input in shell command
	cmd := exec.Command("sh", "-c", "ping -c 1 "+hostname)  // Command Injection!
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
		return
	}
	fmt.Fprintf(w, "Output: %s", output)
}


// VULNERABILITY 4: Path Traversal
func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// BAD: No path validation
	filePath := filepath.Join("/var/www/uploads", filename)
	// Attack: file=../../../../etc/passwd

	content, err := ioutil.ReadFile(filePath)  // Path Traversal!
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(content)
}


// VULNERABILITY 5: XML External Entity (XXE)
type User struct {
	XMLName xml.Name `xml:"user"`
	Name    string   `xml:"name"`
	Email   string   `xml:"email"`
}

func parseXML(xmlData []byte) (*User, error) {
	var user User

	// BAD: XXE not disabled
	err := xml.Unmarshal(xmlData, &user)  // XXE vulnerability!
	if err != nil {
		return nil, err
	}
	return &user, nil
}


// VULNERABILITY 6: Weak Cryptography
func hashPasswordMD5(password string) string {
	// BAD: MD5 is cryptographically broken
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])  // Weak hashing!
}


// VULNERABILITY 7: Insecure Random Number Generation
func generateToken() string {
	// BAD: math/rand is not cryptographically secure
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int())  // Predictable!
}

func generateSessionID() string {
	// BAD: Predictable session ID
	return fmt.Sprintf("%d", time.Now().UnixNano())
}


// VULNERABILITY 8: Missing Authentication
func deleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")

	// BAD: No authentication or authorization check
	db, _ := sql.Open("mysql", "root:"+DBPassword+"@tcp(localhost:3306)/mydb")
	defer db.Close()

	query := fmt.Sprintf("DELETE FROM users WHERE id = %s", userID)
	db.Exec(query)  // No auth + SQL injection!

	fmt.Fprintf(w, "User deleted")
}


// VULNERABILITY 9: SSRF (Server-Side Request Forgery)
func fetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	// BAD: No URL validation
	resp, err := http.Get(url)  // SSRF vulnerability!
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}


// VULNERABILITY 10: Open Redirect
func redirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	// BAD: No whitelist validation
	http.Redirect(w, r, url, http.StatusFound)  // Open redirect!
}


// VULNERABILITY 11: Race Condition
var counter int = 0

func incrementCounter() {
	// BAD: No synchronization
	counter++  // Race condition!
}


// VULNERABILITY 12: Information Disclosure
func errorHandler(w http.ResponseWriter, r *http.Request) {
	// BAD: Exposing sensitive error information
	err := doSomething()
	if err != nil {
		// Never expose detailed error messages
		fmt.Fprintf(w, "Error: %v", err)  // Information disclosure!

		// BAD: Exposing environment variables
		fmt.Fprintf(w, "\nEnvironment: %v", os.Environ())
	}
}


// VULNERABILITY 13: Time-of-Check Time-of-Use (TOCTOU)
func processFile(filename string) error {
	// Time-of-check
	if _, err := os.Stat(filename); err == nil {
		// BAD: Time gap between check and use
		time.Sleep(1 * time.Second)

		// Time-of-use
		content, _ := ioutil.ReadFile(filename)  // TOCTOU race condition!
		fmt.Println(string(content))
	}
	return nil
}


// VULNERABILITY 14: Insecure File Permissions
func createFile(filename string) error {
	// BAD: World-writable permissions
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0777)  // Insecure permissions!
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("sensitive data")
	return nil
}


// VULNERABILITY 15: Memory Disclosure
var secretData = []byte("super_secret_password")

func getSecret() []byte {
	// BAD: Returning pointer to sensitive data
	return secretData  // Memory disclosure - caller can modify!
}


// VULNERABILITY 16: Denial of Service (DoS)
func allocateMemory(w http.ResponseWriter, r *http.Request) {
	size := r.URL.Query().Get("size")

	// BAD: No limit on allocation size
	var sizeInt int
	fmt.Sscanf(size, "%d", &sizeInt)

	data := make([]byte, sizeInt)  // DoS - unbounded allocation!
	w.Write(data)
}


// VULNERABILITY 17: Unvalidated Input in Regex
func validateEmail(email string) bool {
	// BAD: Catastrophic backtracking - ReDoS
	pattern := `^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$`

	// This can cause exponential time complexity
	matched, _ := regexp.MatchString(pattern, email)  // ReDoS!
	return matched
}


// VULNERABILITY 18: Improper Error Handling
func riskyOperation() {
	file, _ := os.Open("important.txt")  // BAD: Ignoring error!

	// file might be nil here
	content := make([]byte, 100)
	file.Read(content)  // Panic if file is nil!
	file.Close()
}


// VULNERABILITY 19: Use After Free (Goroutine Context)
func insecureGoroutine() {
	data := make([]byte, 100)

	go func() {
		time.Sleep(1 * time.Second)
		// BAD: Accessing data that might be garbage collected
		fmt.Println(string(data))
	}()

	// data goes out of scope
}


// VULNERABILITY 20: Template Injection
import "html/template"

func renderTemplate(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("name")

	// BAD: User input directly in template
	tmpl := template.Must(template.New("greeting").Parse(
		"<h1>Hello " + userInput + "</h1>",  // XSS vulnerability!
	))
	tmpl.Execute(w, nil)
}


// VULNERABILITY 21: Insecure Cookie Settings
func setInsecureCookie(w http.ResponseWriter) {
	// BAD: No Secure or HttpOnly flags
	cookie := &http.Cookie{
		Name:     "session",
		Value:    generateToken(),
		HttpOnly: false,  // Accessible via JavaScript!
		Secure:   false,  // Sent over HTTP!
		SameSite: http.SameSiteNoneMode,  // CSRF vulnerable!
	}
	http.SetCookie(w, cookie)
}


// VULNERABILITY 22: Integer Overflow
func calculateTotal(quantity int32, price int32) int32 {
	// BAD: No overflow check
	return quantity * price  // Integer overflow possible!
}


// VULNERABILITY 23: Nil Pointer Dereference
func processUser(user *User) string {
	// BAD: No nil check
	return user.Name  // Panic if user is nil!
}


// Helper function
func doSomething() error {
	return fmt.Errorf("detailed internal error with stack trace")
}


// VULNERABILITY 24: Insecure TLS Configuration
import (
	"crypto/tls"
	"net/http"
)

func createInsecureClient() *http.Client {
	// BAD: Disabling certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,  // Vulnerable to MITM!
			MinVersion:         tls.VersionTLS10,  // Weak TLS version!
		},
	}
	return &http.Client{Transport: tr}
}


func main() {
	http.HandleFunc("/ping", pingHost)
	http.HandleFunc("/download", downloadFile)
	http.HandleFunc("/delete", deleteUser)
	http.HandleFunc("/fetch", fetchURL)
	http.HandleFunc("/redirect", redirect)
	http.HandleFunc("/allocate", allocateMemory)

	// BAD: Running on all interfaces without TLS
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)  // No TLS!
}
