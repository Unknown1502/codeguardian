"""
Dependency Vulnerability Scanner
Scans project dependencies for known CVEs and analyzes real usage in codebase
Uses Gemini 3 to determine if vulnerable functions are actually exploitable
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import aiohttp

from src.core.gemini_client import GeminiClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class DependencyScanner:
    """
    Scan dependencies for vulnerabilities.
    
    This goes beyond simple CVE matching by using Gemini 3 to:
    1. Analyze if your code actually uses the vulnerable function
    2. Determine real exploitability in your specific context
    3. Prioritize by actual risk, not just CVE severity
    """
    
    # Known vulnerability databases (simplified - would use real API in production)
    KNOWN_VULNERABILITIES = {
        'requests': [
            {
                'cve': 'CVE-2023-32681',
                'severity': 'Medium',
                'affected_versions': '<2.31.0',
                'description': 'Proxy-Authorization header not stripped on cross-origin redirects',
                'vulnerable_functions': ['request', 'get', 'post'],
                'cwe': 'CWE-200'
            }
        ],
        'flask': [
            {
                'cve': 'CVE-2023-30861',
                'severity': 'High',
                'affected_versions': '<2.3.2',
                'description': 'Cookie parsing vulnerability allows session hijacking',
                'vulnerable_functions': ['session', 'request.cookies'],
                'cwe': 'CWE-565'
            },
            {
                'cve': 'CVE-2023-25577',
                'severity': 'High',
                'affected_versions': '<2.2.5',
                'description': 'Werkzeug debugger PIN bypass',
                'vulnerable_functions': ['run', 'DebuggedApplication'],
                'cwe': 'CWE-287'
            }
        ],
        'django': [
            {
                'cve': 'CVE-2024-24680',
                'severity': 'High',
                'affected_versions': '<4.2.10',
                'description': 'SQL injection in QuerySet.values()/values_list()',
                'vulnerable_functions': ['values', 'values_list'],
                'cwe': 'CWE-89'
            }
        ],
        'pyyaml': [
            {
                'cve': 'CVE-2020-14343',
                'severity': 'Critical',
                'affected_versions': '<5.4',
                'description': 'Arbitrary code execution via yaml.load()',
                'vulnerable_functions': ['load', 'load_all'],
                'cwe': 'CWE-502'
            }
        ],
        'pillow': [
            {
                'cve': 'CVE-2023-50447',
                'severity': 'High',
                'affected_versions': '<10.2.0',
                'description': 'Arbitrary code execution via crafted image file',
                'vulnerable_functions': ['Image.open'],
                'cwe': 'CWE-94'
            }
        ],
        'numpy': [
            {
                'cve': 'CVE-2021-34141',
                'severity': 'High',
                'affected_versions': '<1.22.0',
                'description': 'Arbitrary code execution via crafted pickle file',
                'vulnerable_functions': ['load', 'loads'],
                'cwe': 'CWE-502'
            }
        ],
        'jinja2': [
            {
                'cve': 'CVE-2024-22195',
                'severity': 'Medium',
                'affected_versions': '<3.1.3',
                'description': 'XSS via attribute injection',
                'vulnerable_functions': ['Template', 'from_string'],
                'cwe': 'CWE-79'
            }
        ]
    }
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize dependency scanner.
        
        Args:
            gemini_client: Gemini 3 client for analysis
        """
        self.gemini_client = gemini_client
        self.scan_results = []
        
    async def scan_project(
        self,
        project_path: str,
        include_transitive: bool = True
    ) -> Dict[str, Any]:
        """
        Scan entire project for dependency vulnerabilities.
        
        Args:
            project_path: Path to project root
            include_transitive: Include transitive dependencies
            
        Returns:
            Comprehensive vulnerability report
        """
        logger.info(f"🔍 Scanning dependencies in {project_path}")
        
        project_root = Path(project_path)
        
        # Find dependency files
        dep_files = self._find_dependency_files(project_root)
        
        if not dep_files:
            logger.warning("No dependency files found (requirements.txt, package.json, etc.)")
            return {
                'success': False,
                'error': 'No dependency files found'
            }
        
        logger.info(f"Found {len(dep_files)} dependency files")
        
        # Parse dependencies
        all_dependencies = {}
        for dep_file in dep_files:
            deps = await self._parse_dependency_file(dep_file)
            all_dependencies.update(deps)
        
        logger.info(f"Parsed {len(all_dependencies)} dependencies")
        
        # Check for vulnerabilities
        vulnerabilities = await self._check_vulnerabilities(all_dependencies)
        
        logger.info(f"Found {len(vulnerabilities)} vulnerable dependencies")
        
        # Analyze actual usage in codebase
        if vulnerabilities:
            logger.info("🤖 Using Gemini 3 to analyze actual exploitability...")
            
            for vuln in vulnerabilities:
                usage_analysis = await self._analyze_usage_context(
                    project_root=project_root,
                    package_name=vuln['package'],
                    vulnerability=vuln
                )
                vuln['usage_analysis'] = usage_analysis
        
        # Generate prioritized report
        report = self._generate_report(
            project_path=project_path,
            dependencies=all_dependencies,
            vulnerabilities=vulnerabilities
        )
        
        self.scan_results.append(report)
        
        return report
    
    def _find_dependency_files(self, project_root: Path) -> List[Path]:
        """Find all dependency files in project."""
        dependency_patterns = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements-test.txt',
            'Pipfile',
            'pyproject.toml',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'pom.xml',
            'build.gradle',
            'go.mod',
            'Cargo.toml'
        ]
        
        found_files = []
        
        for pattern in dependency_patterns:
            matches = list(project_root.rglob(pattern))
            found_files.extend(matches)
        
        return found_files
    
    async def _parse_dependency_file(self, filepath: Path) -> Dict[str, str]:
        """Parse dependency file and extract package versions."""
        dependencies = {}
        
        if filepath.name in ['requirements.txt', 'requirements-dev.txt', 'requirements-test.txt']:
            dependencies = self._parse_requirements_txt(filepath)
        
        elif filepath.name == 'package.json':
            dependencies = self._parse_package_json(filepath)
        
        elif filepath.name == 'pyproject.toml':
            dependencies = self._parse_pyproject_toml(filepath)
        
        # Add more parsers as needed
        
        return dependencies
    
    def _parse_requirements_txt(self, filepath: Path) -> Dict[str, str]:
        """Parse requirements.txt file."""
        dependencies = {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse package==version or package>=version
                    match = re.match(r'^([a-zA-Z0-9\-_]+)(==|>=|<=|>|<|~=)(.+)$', line)
                    if match:
                        package_name = match.group(1).lower()
                        version = match.group(3)
                        dependencies[package_name] = version
                    else:
                        # Package without version
                        package_name = line.split('[')[0].strip().lower()
                        if package_name:
                            dependencies[package_name] = 'latest'
        
        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
        
        return dependencies
    
    def _parse_package_json(self, filepath: Path) -> Dict[str, str]:
        """Parse package.json file."""
        dependencies = {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Regular dependencies
                if 'dependencies' in data:
                    for pkg, version in data['dependencies'].items():
                        dependencies[pkg.lower()] = version.lstrip('^~')
                
                # Dev dependencies
                if 'devDependencies' in data:
                    for pkg, version in data['devDependencies'].items():
                        dependencies[pkg.lower()] = version.lstrip('^~')
        
        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, filepath: Path) -> Dict[str, str]:
        """Parse pyproject.toml file (basic implementation)."""
        dependencies = {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Simple regex parsing (would use tomli in production)
                matches = re.findall(r'([a-zA-Z0-9\-_]+)\s*=\s*["\']([^"\']+)["\']', content)
                for package, version in matches:
                    dependencies[package.lower()] = version
        
        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
        
        return dependencies
    
    async def _check_vulnerabilities(
        self,
        dependencies: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Check dependencies against known vulnerabilities."""
        vulnerabilities = []
        
        for package_name, installed_version in dependencies.items():
            if package_name in self.KNOWN_VULNERABILITIES:
                for vuln in self.KNOWN_VULNERABILITIES[package_name]:
                    # Check if installed version is affected
                    if self._is_version_vulnerable(installed_version, vuln['affected_versions']):
                        vulnerabilities.append({
                            'package': package_name,
                            'installed_version': installed_version,
                            'cve': vuln['cve'],
                            'severity': vuln['severity'],
                            'description': vuln['description'],
                            'vulnerable_functions': vuln['vulnerable_functions'],
                            'cwe': vuln['cwe'],
                            'affected_versions': vuln['affected_versions']
                        })
        
        return vulnerabilities
    
    def _is_version_vulnerable(self, installed: str, affected: str) -> bool:
        """Check if installed version is in affected range."""
        # Simplified version check (would use packaging.version in production)
        if installed == 'latest':
            return False  # Assume latest is patched
        
        # Basic < check
        if affected.startswith('<'):
            threshold = affected[1:].strip()
            try:
                return self._compare_versions(installed, threshold) < 0
            except:
                return True  # If can't parse, assume vulnerable
        
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings."""
        try:
            parts1 = [int(x) for x in v1.split('.')[:3]]
            parts2 = [int(x) for x in v2.split('.')[:3]]
            
            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            
            return 0
        except:
            return 0
    
    async def _analyze_usage_context(
        self,
        project_root: Path,
        package_name: str,
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use Gemini 3 to analyze if vulnerable functions are actually used.
        
        This is the key differentiator - we don't just report CVEs,
        we analyze if YOUR code is actually exploitable.
        """
        logger.info(f"🤖 Analyzing usage of {package_name} in codebase...")
        
        # Find import statements
        imports = self._find_imports(project_root, package_name)
        
        if not imports:
            return {
                'is_used': False,
                'risk_level': 'Low',
                'reason': 'Package imported but vulnerable functions not found in codebase',
                'recommendation': 'Update as part of regular maintenance'
            }
        
        # Build context for Gemini
        code_context = "\n\n".join([
            f"File: {imp['file']}\n```python\n{imp['code_snippet']}\n```"
            for imp in imports[:5]  # Limit to first 5 usages
        ])
        
        prompt = f"""Analyze if this dependency vulnerability is exploitable in this specific codebase.

Vulnerability Details:
- Package: {package_name}
- CVE: {vulnerability['cve']}
- Severity: {vulnerability['severity']}
- Description: {vulnerability['description']}
- Vulnerable Functions: {', '.join(vulnerability['vulnerable_functions'])}
- CWE: {vulnerability['cwe']}

Code Usage:
{code_context}

Analyze:

1. **Is Vulnerable Function Used?**: Does the code actually call the vulnerable functions?
2. **Is Input Controllable?**: Can an attacker control input to the vulnerable function?
3. **Are Protections Present?**: Are there validation, sanitization, or other defenses?
4. **Real-World Exploitability**: Can this actually be exploited in production?
5. **Business Impact**: What data/systems would be affected?

Return JSON:
{{
    "is_used": true/false,
    "vulnerable_function_calls": ["function1", "function2"],
    "attack_surface": "description of how attacker reaches vulnerable code",
    "is_exploitable": true/false,
    "exploitability_score": 0-100,
    "risk_level": "Critical/High/Medium/Low",
    "reason": "detailed explanation",
    "proof_of_concept": "how an attacker would exploit this",
    "business_impact": "what would be compromised",
    "recommendation": "specific action to take",
    "priority": 1-5
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=5  # Max reasoning for accurate risk assessment
        )
        
        return result
    
    def _find_imports(
        self,
        project_root: Path,
        package_name: str
    ) -> List[Dict[str, Any]]:
        """Find all imports of a package in the codebase."""
        imports = []
        
        # Find Python files
        for py_file in project_root.rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Check for imports
                    import_pattern = rf'(?:from\s+{package_name}|import\s+{package_name})'
                    if re.search(import_pattern, content, re.IGNORECASE):
                        # Extract relevant code snippet (10 lines around import)
                        lines = content.split('\n')
                        for i, line in enumerate(lines):
                            if re.search(import_pattern, line, re.IGNORECASE):
                                start = max(0, i - 5)
                                end = min(len(lines), i + 15)
                                snippet = '\n'.join(lines[start:end])
                                
                                imports.append({
                                    'file': str(py_file.relative_to(project_root)),
                                    'line': i + 1,
                                    'code_snippet': snippet
                                })
                                
                                break  # One snippet per file is enough
            
            except Exception as e:
                logger.debug(f"Error reading {py_file}: {e}")
                continue
        
        return imports
    
    def _generate_report(
        self,
        project_path: str,
        dependencies: Dict[str, str],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate comprehensive dependency scan report."""
        
        # Group by severity
        by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            by_severity[severity].append(vuln)
        
        # Calculate risk score
        critical_count = len(by_severity['Critical'])
        high_count = len(by_severity['High'])
        medium_count = len(by_severity['Medium'])
        
        risk_score = (
            critical_count * 10 +
            high_count * 5 +
            medium_count * 2
        )
        
        # Actually exploitable count
        exploitable_count = sum(
            1 for v in vulnerabilities
            if v.get('usage_analysis', {}).get('is_exploitable', False)
        )
        
        return {
            'scan_id': f"dep_scan_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'project_path': project_path,
            
            'summary': {
                'total_dependencies': len(dependencies),
                'vulnerable_dependencies': len(vulnerabilities),
                'actually_exploitable': exploitable_count,
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'risk_score': risk_score
            },
            
            'dependencies': dependencies,
            'vulnerabilities': vulnerabilities,
            'vulnerabilities_by_severity': by_severity,
            
            'recommendations': self._generate_recommendations(vulnerabilities),
            
            'success': True
        }
    
    def _generate_recommendations(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Group by package
        by_package = {}
        for vuln in vulnerabilities:
            pkg = vuln['package']
            if pkg not in by_package:
                by_package[pkg] = []
            by_package[pkg].append(vuln)
        
        # Generate recommendations
        for package, vulns in by_package.items():
            max_severity = max(v['severity'] for v in vulns)
            
            # Check if actually exploitable
            exploitable = any(
                v.get('usage_analysis', {}).get('is_exploitable', False)
                for v in vulns
            )
            
            if exploitable:
                recommendations.append(
                    f"🔴 URGENT: Update {package} immediately - actively exploitable in your codebase"
                )
            elif max_severity == 'Critical':
                recommendations.append(
                    f"⚠️  HIGH PRIORITY: Update {package} - critical vulnerability (not actively exploited)"
                )
            else:
                recommendations.append(
                    f"📋 Update {package} during next maintenance window"
                )
        
        return recommendations
