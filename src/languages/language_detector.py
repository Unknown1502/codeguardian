"""
Language Detector - Automatically detect programming languages from files
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class LanguageDetector:
    """
    Detect programming languages from file extensions and content.
    
    Supports: Python, JavaScript, TypeScript, Go, Java, PHP, and more.
    """
    
    # File extension to language mapping
    EXTENSION_MAP = {
        # Python
        '.py': 'python',
        '.pyw': 'python',
        '.pyx': 'python',
        
        # JavaScript/TypeScript
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        
        # Go
        '.go': 'go',
        
        # Java
        '.java': 'java',
        '.jar': 'java',
        
        # PHP
        '.php': 'php',
        '.phtml': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        
        # C/C++
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cxx': 'cpp',
        '.cc': 'cpp',
        '.hpp': 'cpp',
        
        # Ruby
        '.rb': 'ruby',
        '.rake': 'ruby',
        
        # Rust
        '.rs': 'rust',
        
        # C#
        '.cs': 'csharp',
        
        # Shell
        '.sh': 'shell',
        '.bash': 'shell',
        
        # SQL
        '.sql': 'sql'
    }
    
    # Content-based detection patterns
    CONTENT_PATTERNS = {
        'python': [
            r'^\s*import\s+\w+',
            r'^\s*from\s+\w+\s+import',
            r'^\s*def\s+\w+\s*\(',
            r'^\s*class\s+\w+\s*[:(]'
        ],
        'javascript': [
            r'^\s*const\s+\w+\s*=',
            r'^\s*let\s+\w+\s*=',
            r'^\s*var\s+\w+\s*=',
            r'^\s*function\s+\w+\s*\(',
            r'require\s*\([\'"]',
            r'export\s+(default|const|function|class)',
            r'import\s+.*\s+from\s+[\'"]'
        ],
        'typescript': [
            r':\s*(string|number|boolean|any)\s*[;=]',
            r'interface\s+\w+\s*{',
            r'type\s+\w+\s*=',
            r'<.*>\s*\(',
            r'as\s+(string|number|boolean|any)'
        ],
        'go': [
            r'^\s*package\s+\w+',
            r'^\s*import\s+\(',
            r'^\s*func\s+\w+\s*\(',
            r'^\s*type\s+\w+\s+struct',
            r':=\s*'
        ],
        'java': [
            r'^\s*public\s+class\s+\w+',
            r'^\s*private\s+\w+\s+\w+',
            r'^\s*import\s+[\w.]+;',
            r'^\s*package\s+[\w.]+;',
            r'System\.out\.println'
        ],
        'php': [
            r'<\?php',
            r'\$\w+\s*=',
            r'function\s+\w+\s*\(',
            r'class\s+\w+\s*{',
            r'->\w+',
            r'::\w+'
        ]
    }
    
    @classmethod
    def detect_from_file(cls, filepath: str) -> Tuple[str, float]:
        """
        Detect language from file.
        
        Args:
            filepath: Path to file
            
        Returns:
            Tuple of (language, confidence) where confidence is 0-1
        """
        path = Path(filepath)
        
        # First try extension
        extension = path.suffix.lower()
        if extension in cls.EXTENSION_MAP:
            language = cls.EXTENSION_MAP[extension]
            
            # If extension is ambiguous (like .h), check content
            if extension in ['.h', '.js']:
                content_lang, content_conf = cls.detect_from_content(filepath)
                if content_conf > 0.5:
                    return content_lang, content_conf
            
            return language, 0.9
        
        # Try content-based detection
        return cls.detect_from_content(filepath)
    
    @classmethod
    def detect_from_content(cls, filepath: str, max_lines: int = 100) -> Tuple[str, float]:
        """
        Detect language from file content.
        
        Args:
            filepath: Path to file
            max_lines: Maximum lines to read
            
        Returns:
            Tuple of (language, confidence)
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = '\n'.join(f.readlines()[:max_lines])
        except Exception as e:
            logger.debug(f"Could not read {filepath}: {e}")
            return 'unknown', 0.0
        
        # Count pattern matches for each language
        scores = {}
        
        for language, patterns in cls.CONTENT_PATTERNS.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE):
                    matches += 1
            
            if matches > 0:
                scores[language] = matches
        
        if not scores:
            return 'unknown', 0.0
        
        # Get language with highest score
        best_language = max(scores, key=scores.get)
        max_patterns = len(cls.CONTENT_PATTERNS[best_language])
        confidence = min(scores[best_language] / max_patterns, 1.0)
        
        return best_language, confidence
    
    @classmethod
    def scan_directory(cls, directory: str, recursive: bool = True) -> Dict[str, List[str]]:
        """
        Scan directory and group files by language.
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            
        Returns:
            Dict mapping language -> list of files
        """
        dir_path = Path(directory)
        files_by_language = {}
        
        # Get all files
        if recursive:
            all_files = dir_path.rglob('*')
        else:
            all_files = dir_path.glob('*')
        
        # Filter only files (not directories)
        files = [f for f in all_files if f.is_file()]
        
        for filepath in files:
            # Skip common non-code files
            if filepath.name.startswith('.'):
                continue
            
            if filepath.suffix.lower() in ['.md', '.txt', '.json', '.yaml', '.yml', '.xml', '.csv']:
                continue
            
            language, confidence = cls.detect_from_file(str(filepath))
            
            if confidence > 0.3:  # Minimum confidence threshold
                if language not in files_by_language:
                    files_by_language[language] = []
                files_by_language[language].append(str(filepath))
        
        return files_by_language
    
    @classmethod
    def is_supported(cls, language: str) -> bool:
        """Check if language is supported for security scanning."""
        supported = ['python', 'javascript', 'typescript', 'go', 'java', 'php']
        return language.lower() in supported
    
    @classmethod
    def get_supported_languages(cls) -> List[str]:
        """Get list of supported languages."""
        return ['python', 'javascript', 'typescript', 'go', 'java', 'php']
    
    @classmethod
    def get_file_extensions(cls, language: str) -> List[str]:
        """Get file extensions for a language."""
        extensions = []
        for ext, lang in cls.EXTENSION_MAP.items():
            if lang.lower() == language.lower():
                extensions.append(ext)
        return extensions
