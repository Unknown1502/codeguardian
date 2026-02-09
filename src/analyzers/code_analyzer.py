"""
Codebase Analyzer
Parses and analyzes entire codebases to extract:
- File structures
- Dependencies
- Data flows
- Security-critical code paths
Uses Gemini 3's 1M token context to understand the full codebase
"""

import os
import ast
from pathlib import Path
from typing import Dict, List, Any, Set
import asyncio

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class CodebaseAnalyzer:
    """
    Analyzes entire codebases to build comprehensive understanding.
    Designed to work with Gemini 3's 1M token context window.
    """
    
    def __init__(self, root_path: Path, language: str = 'auto'):
        """
        Initialize codebase analyzer.
        
        Args:
            root_path: Root directory of codebase to analyze
            language: Primary language (auto, python, javascript, java)
        """
        self.root_path = Path(root_path)
        self.language = language
        
        # Analysis results
        self.files = []
        self.dependencies = {}
        self.data_flows = []
        self.critical_paths = []
        
        # Language-specific parsers
        self.parsers = {
            'python': self._parse_python,
            'javascript': self._parse_javascript,
            'java': self._parse_java
        }
        
    async def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive codebase analysis.
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting codebase analysis: {self.root_path}")
        
        # Step 1: Discover files
        await self._discover_files()
        
        # Step 2: Parse each file
        await self._parse_files()
        
        # Step 3: Build dependency graph
        await self._build_dependency_graph()
        
        # Step 4: Identify data flows
        await self._identify_data_flows()
        
        # Step 5: Find security-critical paths
        await self._find_critical_paths()
        
        # Calculate metrics
        total_loc = sum(f['loc'] for f in self.files)
        total_tokens = self._estimate_tokens(total_loc)
        
        result = {
            'root_path': str(self.root_path),
            'language': self.language,
            'files': self.files,
            'files_count': len(self.files),
            'total_loc': total_loc,
            'total_tokens': total_tokens,
            'dependencies': self.dependencies,
            'data_flows': self.data_flows,
            'critical_paths': self.critical_paths,
            'supported_languages': self._detect_languages()
        }
        
        logger.info(f"Analysis complete: {len(self.files)} files, {total_loc:,} LOC, ~{total_tokens:,} tokens")
        
        return result
    
    async def _discover_files(self) -> None:
        """Discover all relevant source files."""
        
        # Extensions to analyze
        code_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', 
            '.java', '.c', '.cpp', '.cs', '.go',
            '.rb', '.php', '.swift', '.kt'
        }
        
        # Directories to skip
        skip_dirs = {
            'node_modules', 'venv', 'env', '.git', 
            '__pycache__', 'dist', 'build', '.next',
            'vendor', 'target'
        }
        
        # Handle single file case
        if self.root_path.is_file():
            ext = self.root_path.suffix
            if ext in code_extensions:
                self.files.append({
                    'path': str(self.root_path),
                    'relative_path': self.root_path.name,
                    'name': self.root_path.name,
                    'extension': ext,
                    'size': self.root_path.stat().st_size,
                    'loc': 0,  # Will be calculated during parsing
                    'parsed': False,
                    'ast': None,
                    'imports': [],
                    'functions': [],
                    'classes': []
                })
            return
        
        # Handle directory case
        for root, dirs, files in os.walk(self.root_path):
            # Filter out skip directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                ext = Path(file).suffix
                if ext in code_extensions:
                    file_path = Path(root) / file
                    self.files.append({
                        'path': str(file_path),
                        'relative_path': str(file_path.relative_to(self.root_path)),
                        'name': file,
                        'extension': ext,
                        'size': file_path.stat().st_size,
                        'loc': 0,  # Will be calculated during parsing
                        'parsed': False,
                        'ast': None,
                        'imports': [],
                        'functions': [],
                        'classes': []
                    })
    
    async def _parse_files(self) -> None:
        """Parse each discovered file."""
        
        tasks = []
        for file_info in self.files:
            task = self._parse_file(file_info)
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _parse_file(self, file_info: Dict[str, Any]) -> None:
        """Parse a single file based on its language."""
        
        try:
            # Read file content
            with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Count lines of code
            lines = content.split('\n')
            file_info['loc'] = len([l for l in lines if l.strip() and not l.strip().startswith('#')])
            
            # Parse based on extension
            if file_info['extension'] == '.py':
                await self._parse_python(file_info, content)
            elif file_info['extension'] in ['.js', '.jsx', '.ts', '.tsx']:
                await self._parse_javascript(file_info, content)
            elif file_info['extension'] == '.java':
                await self._parse_java(file_info, content)
            
            file_info['parsed'] = True
            
        except Exception as e:
            logger.warning(f"Failed to parse {file_info['path']}: {e}")
            file_info['parsed'] = False
    
    async def _parse_python(self, file_info: Dict[str, Any], content: str) -> None:
        """Parse Python file using AST."""
        
        try:
            tree = ast.parse(content)
            file_info['ast'] = tree
            
            # Extract imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        file_info['imports'].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        file_info['imports'].append(node.module)
            
            # Extract functions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    file_info['functions'].append({
                        'name': node.name,
                        'line': node.lineno,
                        'args': [arg.arg for arg in node.args.args],
                        'decorators': [d.id if isinstance(d, ast.Name) else '' for d in node.decorator_list]
                    })
            
            # Extract classes
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    file_info['classes'].append({
                        'name': node.name,
                        'line': node.lineno,
                        'methods': [m.name for m in node.body if isinstance(m, ast.FunctionDef)]
                    })
                    
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_info['path']}: {e}")
    
    async def _parse_javascript(self, file_info: Dict[str, Any], content: str) -> None:
        """Parse JavaScript/TypeScript file (basic extraction)."""
        
        # Simple regex-based extraction for demo
        # In production, use a proper JS parser like esprima
        
        import re
        
        # Extract imports
        import_pattern = r"import\s+.*?\s+from\s+['\"](.+?)['\"]"
        file_info['imports'] = re.findall(import_pattern, content)
        
        # Extract function declarations
        func_pattern = r"function\s+(\w+)\s*\("
        file_info['functions'] = [{'name': f} for f in re.findall(func_pattern, content)]
    
    async def _parse_java(self, file_info: Dict[str, Any], content: str) -> None:
        """Parse Java file (basic extraction)."""
        
        import re
        
        # Extract imports
        import_pattern = r"import\s+([\w.]+);"
        file_info['imports'] = re.findall(import_pattern, content)
        
        # Extract class names
        class_pattern = r"class\s+(\w+)"
        file_info['classes'] = [{'name': c} for c in re.findall(class_pattern, content)]
    
    async def _build_dependency_graph(self) -> None:
        """Build dependency graph from imports."""
        
        for file_info in self.files:
            file_path = file_info['relative_path']
            self.dependencies[file_path] = file_info['imports']
    
    async def _identify_data_flows(self) -> None:
        """Identify data flows through the codebase."""
        
        # Look for common data flow patterns
        for file_info in self.files:
            for func in file_info.get('functions', []):
                # Check if function deals with external input
                if any(keyword in func['name'].lower() for keyword in ['input', 'request', 'param', 'query']):
                    self.data_flows.append({
                        'type': 'external_input',
                        'file': file_info['relative_path'],
                        'function': func['name'],
                        'line': func.get('line', 0)
                    })
    
    async def _find_critical_paths(self) -> None:
        """Identify security-critical code paths."""
        
        # Patterns that indicate security-critical code
        critical_patterns = [
            'auth', 'login', 'password', 'token', 'session',
            'admin', 'permission', 'sql', 'query', 'exec',
            'eval', 'serialize', 'deserialize', 'upload',
            'download', 'file', 'path', 'command'
        ]
        
        for file_info in self.files:
            # Check functions
            for func in file_info.get('functions', []):
                if any(pattern in func['name'].lower() for pattern in critical_patterns):
                    self.critical_paths.append({
                        'type': 'function',
                        'file': file_info['relative_path'],
                        'name': func['name'],
                        'line': func.get('line', 0),
                        'reason': 'Name suggests security-critical operation'
                    })
            
            # Check imports
            for imp in file_info.get('imports', []):
                if any(pattern in imp.lower() for pattern in ['sql', 'crypto', 'auth', 'security']):
                    self.critical_paths.append({
                        'type': 'import',
                        'file': file_info['relative_path'],
                        'name': imp,
                        'reason': 'Security-related library'
                    })
    
    def _detect_languages(self) -> List[str]:
        """Detect all programming languages in codebase."""
        
        ext_to_lang = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.jsx': 'JavaScript',
            '.ts': 'TypeScript',
            '.tsx': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.cs': 'C#',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP'
        }
        
        languages = set()
        for file_info in self.files:
            lang = ext_to_lang.get(file_info['extension'])
            if lang:
                languages.add(lang)
        
        return sorted(list(languages))
    
    def _estimate_tokens(self, loc: int) -> int:
        """Estimate token count from lines of code."""
        # Rough estimate: ~10 tokens per line of code
        return loc * 10
    
    def get_file_content(self, file_path: str) -> str:
        """Get content of a specific file."""
        
        try:
            full_path = self.root_path / file_path
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return ""
    
    def get_context_for_file(self, file_path: str, lines_before: int = 10, lines_after: int = 10) -> str:
        """Get file content with surrounding context."""
        
        content = self.get_file_content(file_path)
        if not content:
            return ""
        
        # For now, return full content
        # In production, implement smart context window management
        return content
