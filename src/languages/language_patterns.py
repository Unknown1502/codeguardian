"""
Language-Specific Vulnerability Patterns
Defines OWASP Top 10 and common vulnerabilities for each supported language
"""

from typing import Dict, List, Any


class LanguagePatterns:
    """
    Language-specific vulnerability patterns and dangerous functions.
    
    Each language has different APIs and frameworks that introduce security risks.
    """
    
    # Python vulnerability patterns
    PYTHON_PATTERNS = {
        'sql_injection': {
            'patterns': [
                r'execute\s*\(\s*[f"\'].*%.*[f"\']',
                r'cursor\.execute\s*\(\s*[f"\'].*\+',
                r'raw\s*\(\s*[f"\'].*%',
                r'filter\s*\(\s*.*\+',
            ],
            'dangerous_functions': ['execute', 'executemany', 'raw', 'extra'],
            'safe_alternatives': ['parameterized queries', 'ORM methods'],
            'cwe': 'CWE-89'
        },
        'command_injection': {
            'patterns': [
                r'os\.system\s*\(',
                r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\('
            ],
            'dangerous_functions': ['os.system', 'eval', 'exec', 'subprocess with shell=True'],
            'safe_alternatives': ['subprocess.run with list args', 'ast.literal_eval'],
            'cwe': 'CWE-78'
        },
        'deserialization': {
            'patterns': [
                r'pickle\.loads?\s*\(',
                r'yaml\.load\s*\(',
                r'marshal\.loads?\s*\('
            ],
            'dangerous_functions': ['pickle.load', 'yaml.load', 'marshal.load'],
            'safe_alternatives': ['json.loads', 'yaml.safe_load'],
            'cwe': 'CWE-502'
        }
    }
    
    # JavaScript/TypeScript vulnerability patterns
    JAVASCRIPT_PATTERNS = {
        'xss': {
            'patterns': [
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'document\.write\s*\(',
                r'\.html\s*\(',
                r'dangerouslySetInnerHTML'
            ],
            'dangerous_functions': ['innerHTML', 'document.write', 'dangerouslySetInnerHTML'],
            'safe_alternatives': ['textContent', 'createElement', 'DOMPurify.sanitize'],
            'cwe': 'CWE-79'
        },
        'sql_injection': {
            'patterns': [
                r'query\s*\(\s*[`"\'].*\$\{',
                r'execute\s*\(\s*[`"\'].*\$\{',
                r'raw\s*\(\s*[`"\'].*\+',
            ],
            'dangerous_functions': ['raw queries with string concatenation'],
            'safe_alternatives': ['parameterized queries', 'query builders', 'ORMs'],
            'cwe': 'CWE-89'
        },
        'command_injection': {
            'patterns': [
                r'exec\s*\(',
                r'execSync\s*\(',
                r'spawn\s*\([^)]*shell:\s*true',
                r'eval\s*\('
            ],
            'dangerous_functions': ['exec', 'eval', 'child_process with shell'],
            'safe_alternatives': ['execFile', 'spawn with array args'],
            'cwe': 'CWE-78'
        },
        'prototype_pollution': {
            'patterns': [
                r'Object\.assign\s*\(\s*\w+\.prototype',
                r'\[.*\]\s*=.*(?:req\.body|req\.query)',
                r'__proto__',
                r'constructor\.prototype'
            ],
            'dangerous_functions': ['direct prototype manipulation', 'recursive merge'],
            'safe_alternatives': ['Object.create(null)', 'validate keys'],
            'cwe': 'CWE-1321'
        }
    }
    
    # Go vulnerability patterns
    GO_PATTERNS = {
        'sql_injection': {
            'patterns': [
                r'Query\s*\(\s*fmt\.Sprintf',
                r'Exec\s*\(\s*.*\+',
                r'Query\s*\(\s*.*\+',
            ],
            'dangerous_functions': ['fmt.Sprintf with Query', 'string concatenation in SQL'],
            'safe_alternatives': ['Query with ? placeholders', 'Named parameters'],
            'cwe': 'CWE-89'
        },
        'command_injection': {
            'patterns': [
                r'exec\.Command\s*\(\s*"sh".*"-c"',
                r'exec\.Command\s*\(\s*"bash".*"-c"',
            ],
            'dangerous_functions': ['exec.Command with shell'],
            'safe_alternatives': ['exec.Command with direct binary'],
            'cwe': 'CWE-78'
        },
        'path_traversal': {
            'patterns': [
                r'ioutil\.ReadFile\s*\([^)]*\+',
                r'os\.Open\s*\([^)]*\+',
                r'filepath\.Join\s*\([^)]*req\.',
            ],
            'dangerous_functions': ['direct file path from user input'],
            'safe_alternatives': ['filepath.Clean', 'validate path', 'whitelist'],
            'cwe': 'CWE-22'
        }
    }
    
    # Java vulnerability patterns
    JAVA_PATTERNS = {
        'sql_injection': {
            'patterns': [
                r'createStatement\s*\(\s*\)',
                r'executeQuery\s*\(\s*.*\+',
                r'executeUpdate\s*\(\s*.*\+',
            ],
            'dangerous_functions': ['Statement.executeQuery with concatenation'],
            'safe_alternatives': ['PreparedStatement', 'JPA/Hibernate'],
            'cwe': 'CWE-89'
        },
        'xxe': {
            'patterns': [
                r'DocumentBuilderFactory\.newInstance\s*\(\s*\)',
                r'SAXParserFactory\.newInstance\s*\(\s*\)',
                r'XMLInputFactory\.newInstance\s*\(\s*\)',
            ],
            'dangerous_functions': ['XML parsers without XXE protection'],
            'safe_alternatives': ['disable external entities', 'use safe parser config'],
            'cwe': 'CWE-611'
        },
        'deserialization': {
            'patterns': [
                r'ObjectInputStream\s*\(',
                r'readObject\s*\(\s*\)',
                r'XMLDecoder\s*\(',
            ],
            'dangerous_functions': ['ObjectInputStream.readObject'],
            'safe_alternatives': ['JSON', 'validate classes', 'look-ahead deserialization'],
            'cwe': 'CWE-502'
        }
    }
    
    # PHP vulnerability patterns
    PHP_PATTERNS = {
        'sql_injection': {
            'patterns': [
                r'mysql_query\s*\(\s*["\'].*\$',
                r'mysqli_query\s*\(\s*.*["\'].*\.',
                r'\$pdo->query\s*\(\s*["\'].*\$',
            ],
            'dangerous_functions': ['mysql_query with variables', 'string concatenation in SQL'],
            'safe_alternatives': ['PDO with prepared statements', 'mysqli_prepare'],
            'cwe': 'CWE-89'
        },
        'command_injection': {
            'patterns': [
                r'exec\s*\(',
                r'shell_exec\s*\(',
                r'system\s*\(',
                r'passthru\s*\(',
                r'`.*\$',  # backticks
            ],
            'dangerous_functions': ['exec', 'shell_exec', 'system', 'backticks'],
            'safe_alternatives': ['escapeshellarg', 'escapeshellcmd', 'avoid shell'],
            'cwe': 'CWE-78'
        },
        'file_inclusion': {
            'patterns': [
                r'include\s*\(\s*\$',
                r'require\s*\(\s*\$',
                r'include_once\s*\(\s*\$',
                r'require_once\s*\(\s*\$',
            ],
            'dangerous_functions': ['include/require with user input'],
            'safe_alternatives': ['whitelist files', 'validate paths', 'use constants'],
            'cwe': 'CWE-98'
        },
        'code_injection': {
            'patterns': [
                r'eval\s*\(',
                r'assert\s*\(',
                r'preg_replace\s*\([^)]*\/e',
            ],
            'dangerous_functions': ['eval', 'assert', 'preg_replace /e'],
            'safe_alternatives': ['avoid eval', 'use proper parsing'],
            'cwe': 'CWE-94'
        }
    }
    
    @classmethod
    def get_patterns(cls, language: str) -> Dict[str, Any]:
        """Get vulnerability patterns for a language."""
        patterns_map = {
            'python': cls.PYTHON_PATTERNS,
            'javascript': cls.JAVASCRIPT_PATTERNS,
            'typescript': cls.JAVASCRIPT_PATTERNS,  # TypeScript uses same patterns
            'go': cls.GO_PATTERNS,
            'java': cls.JAVA_PATTERNS,
            'php': cls.PHP_PATTERNS
        }
        
        return patterns_map.get(language.lower(), {})
    
    @classmethod
    def get_vulnerability_types(cls, language: str) -> List[str]:
        """Get list of vulnerability types checked for a language."""
        patterns = cls.get_patterns(language)
        return list(patterns.keys())
    
    @classmethod
    def get_dangerous_functions(cls, language: str) -> List[str]:
        """Get list of dangerous functions for a language."""
        patterns = cls.get_patterns(language)
        functions = []
        
        for vuln_type, data in patterns.items():
            functions.extend(data.get('dangerous_functions', []))
        
        return functions
    
    @classmethod
    def get_language_specific_prompt(cls, language: str) -> str:
        """Get language-specific security analysis prompt."""
        
        prompts = {
            'python': """Analyze this Python code for security vulnerabilities including:
- SQL Injection (avoid string formatting in queries)
- Command Injection (os.system, eval, exec)
- Deserialization (pickle.loads, yaml.load)
- Path Traversal (unchecked file paths)
- XXE (XML parsing)

Focus on Python-specific risks like pickle, eval, and subprocess with shell=True.""",
            
            'javascript': """Analyze this JavaScript/Node.js code for security vulnerabilities including:
- XSS (innerHTML, document.write, dangerouslySetInnerHTML)
- SQL Injection (template literals in queries)
- Command Injection (child_process.exec with shell)
- Prototype Pollution (__proto__, Object.assign to prototype)
- Path Traversal (fs operations with user input)
- NoSQL Injection (MongoDB queries)

Focus on JavaScript-specific risks like prototype pollution and async callback vulnerabilities.""",
            
            'typescript': """Analyze this TypeScript code for security vulnerabilities including:
- XSS (innerHTML, DOM manipulation)
- SQL Injection (template literals in queries)
- Command Injection (child_process with shell)
- Prototype Pollution (__proto__ manipulation)
- Type confusion attacks
- Unsafe type assertions

TypeScript's type system can hide vulnerabilities - check runtime behavior.""",
            
            'go': """Analyze this Go code for security vulnerabilities including:
- SQL Injection (string concatenation in queries)
- Command Injection (exec.Command with shell)
- Path Traversal (unchecked file operations)
- Race Conditions (improper goroutine synchronization)
- Integer Overflow
- Improper Error Handling

Focus on Go-specific risks like goroutine races and pointer misuse.""",
            
            'java': """Analyze this Java code for security vulnerabilities including:
- SQL Injection (Statement vs PreparedStatement)
- XXE (XML External Entities in parsers)
- Deserialization (ObjectInputStream.readObject)
- Path Traversal (File operations)
- LDAP Injection
- Reflection abuse

Focus on Java-specific risks like deserialization gadgets and XXE.""",
            
            'php': """Analyze this PHP code for security vulnerabilities including:
- SQL Injection (mysqli_query, mysql_query with variables)
- Command Injection (exec, shell_exec, system)
- File Inclusion (include, require with user input)
- Code Injection (eval, assert)
- XSS (echo user data)
- SSRF (file_get_contents, curl with user URLs)

Focus on PHP-specific risks like file inclusion and magic quotes."""
        }
        
        return prompts.get(language.lower(), 
                          f"Analyze this {language} code for security vulnerabilities.")
    
    @classmethod
    def get_framework_context(cls, language: str) -> List[str]:
        """Get common frameworks for a language to provide context."""
        
        frameworks = {
            'python': ['Django', 'Flask', 'FastAPI', 'SQLAlchemy', 'Requests'],
            'javascript': ['Express.js', 'React', 'Vue', 'Angular', 'Next.js', 'Nest.js'],
            'typescript': ['Express.js', 'React', 'Angular', 'Nest.js', 'TypeORM'],
            'go': ['Gin', 'Echo', 'Fiber', 'GORM', 'Chi'],
            'java': ['Spring Boot', 'Hibernate', 'Apache Struts', 'JSF', 'JDBC'],
            'php': ['Laravel', 'Symfony', 'CodeIgniter', 'WordPress', 'Drupal']
        }
        
        return frameworks.get(language.lower(), [])
