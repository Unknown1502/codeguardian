"""
Multi-Language Security Scanner
Scans code in multiple programming languages using Gemini 3
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.core.gemini_client import GeminiClient
from src.languages.language_detector import LanguageDetector
from src.languages.language_patterns import LanguagePatterns
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class MultiLanguageScanner:
    """
    Scan projects containing multiple programming languages.
    
    Uses Gemini 3 with language-specific prompts and patterns for:
    - Python
    - JavaScript/TypeScript
    - Go
    - Java
    - PHP
    """
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize multi-language scanner.
        
        Args:
            gemini_client: Gemini 3 client for analysis
        """
        self.gemini_client = gemini_client
        self.detector = LanguageDetector()
        
    async def scan_project(
        self,
        project_path: str,
        languages: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan entire project supporting multiple languages.
        
        Args:
            project_path: Path to project root
            languages: Optional list of languages to scan (None = auto-detect)
            
        Returns:
            Comprehensive scan results by language
        """
        logger.info(f"🌍 Starting multi-language scan of {project_path}")
        
        project_root = Path(project_path)
        
        if not project_root.exists():
            return {
                'success': False,
                'error': f'Project path does not exist: {project_path}'
            }
        
        # Detect languages in project
        logger.info("🔍 Detecting languages...")
        files_by_language = self.detector.scan_directory(str(project_root))
        
        # Filter to supported languages
        supported = [lang for lang in files_by_language.keys() 
                    if self.detector.is_supported(lang)]
        
        if languages:
            # User specified languages
            supported = [lang for lang in supported if lang in languages]
        
        if not supported:
            return {
                'success': False,
                'error': 'No supported languages found',
                'detected_languages': list(files_by_language.keys())
            }
        
        logger.info(f"📋 Found {len(supported)} supported languages: {', '.join(supported)}")
        
        # Scan each language
        results_by_language = {}
        total_vulnerabilities = 0
        
        for language in supported:
            files = files_by_language[language]
            logger.info(f"\n🔍 Scanning {len(files)} {language} files...")
            
            lang_results = await self._scan_language(
                language=language,
                files=files,
                project_root=project_root
            )
            
            results_by_language[language] = lang_results
            total_vulnerabilities += lang_results['summary']['total_vulnerabilities']
        
        # Generate combined report
        report = self._generate_multi_language_report(
            project_path=project_path,
            results_by_language=results_by_language,
            total_vulnerabilities=total_vulnerabilities
        )
        
        logger.info(f"\n✅ Multi-language scan complete!")
        logger.info(f"   Total files scanned: {sum(len(files_by_language.get(l, [])) for l in supported)}")
        logger.info(f"   Total vulnerabilities: {total_vulnerabilities}")
        
        return report
    
    async def _scan_language(
        self,
        language: str,
        files: List[str],
        project_root: Path
    ) -> Dict[str, Any]:
        """Scan files for a specific language."""
        
        all_vulnerabilities = []
        files_scanned = 0
        files_with_issues = 0
        
        # Scan each file
        for filepath in files[:20]:  # Limit to 20 files per language to avoid token limits
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                # Skip very large files
                if len(code) > 50000:
                    logger.debug(f"Skipping large file: {filepath}")
                    continue
                
                # Analyze with Gemini
                result = await self._analyze_file(
                    filepath=filepath,
                    code=code,
                    language=language
                )
                
                if result.get('vulnerabilities'):
                    vulnerabilities = result['vulnerabilities']
                    
                    # Add file info
                    for vuln in vulnerabilities:
                        vuln['file'] = str(Path(filepath).relative_to(project_root))
                        vuln['language'] = language
                    
                    all_vulnerabilities.extend(vulnerabilities)
                    files_with_issues += 1
                
                files_scanned += 1
                
                # Small delay between files
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error scanning {filepath}: {e}")
                continue
        
        # Calculate severity distribution
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'language': language,
            'files_scanned': files_scanned,
            'files_with_issues': files_with_issues,
            'vulnerabilities': all_vulnerabilities,
            'summary': {
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical': severity_counts['Critical'],
                'high': severity_counts['High'],
                'medium': severity_counts['Medium'],
                'low': severity_counts['Low']
            }
        }
    
    async def _analyze_file(
        self,
        filepath: str,
        code: str,
        language: str
    ) -> Dict[str, Any]:
        """Analyze a single file for vulnerabilities."""
        
        # Get language-specific context
        patterns = LanguagePatterns.get_patterns(language)
        dangerous_functions = LanguagePatterns.get_dangerous_functions(language)
        frameworks = LanguagePatterns.get_framework_context(language)
        base_prompt = LanguagePatterns.get_language_specific_prompt(language)
        
        # Build comprehensive prompt
        prompt = f"""{base_prompt}

Context:
- Language: {language}
- File: {Path(filepath).name}
- Common frameworks: {', '.join(frameworks)}
- Known dangerous functions: {', '.join(dangerous_functions[:10])}

Code to analyze:
```{language}
{code[:8000]}  
```

Provide detailed vulnerability analysis.

Return JSON:
{{
    "vulnerabilities": [
        {{
            "type": "SQL Injection",
            "severity": "Critical",
            "line": 25,
            "code_snippet": "problematic code line",
            "explanation": "detailed explanation of the vulnerability",
            "exploit": "how an attacker would exploit this",
            "fix": "specific code fix",
            "cwe": "CWE-89",
            "confidence": 95
        }}
    ],
    "code_quality_issues": ["...", "..."],
    "recommendations": ["...", "..."]
}}
"""
        
        try:
            result = await self.gemini_client.analyze_with_extended_reasoning(
                prompt=prompt,
                thinking_level=4
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing {filepath}: {e}")
            return {'vulnerabilities': []}
    
    def _generate_multi_language_report(
        self,
        project_path: str,
        results_by_language: Dict[str, Any],
        total_vulnerabilities: int
    ) -> Dict[str, Any]:
        """Generate comprehensive multi-language report."""
        
        # Aggregate statistics
        total_files = sum(r['files_scanned'] for r in results_by_language.values())
        files_with_issues = sum(r['files_with_issues'] for r in results_by_language.values())
        
        # Severity distribution across all languages
        total_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for lang_results in results_by_language.values():
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                total_severity[severity] += lang_results['summary'].get(severity.lower(), 0)
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        for lang_results in results_by_language.values():
            all_vulnerabilities.extend(lang_results['vulnerabilities'])
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        all_vulnerabilities.sort(key=lambda v: severity_order.get(v.get('severity', 'Medium'), 2))
        
        # Language statistics
        language_stats = {}
        for language, results in results_by_language.items():
            language_stats[language] = {
                'files_scanned': results['files_scanned'],
                'vulnerabilities': results['summary']['total_vulnerabilities'],
                'critical': results['summary']['critical'],
                'high': results['summary']['high'],
                'medium': results['summary']['medium'],
                'low': results['summary']['low']
            }
        
        return {
            'scan_id': f"multi_lang_scan_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'project_path': project_path,
            
            'summary': {
                'languages_scanned': list(results_by_language.keys()),
                'total_files': total_files,
                'files_with_issues': files_with_issues,
                'total_vulnerabilities': total_vulnerabilities,
                'critical': total_severity['Critical'],
                'high': total_severity['High'],
                'medium': total_severity['Medium'],
                'low': total_severity['Low']
            },
            
            'language_statistics': language_stats,
            'results_by_language': results_by_language,
            'all_vulnerabilities': all_vulnerabilities,
            
            'top_issues': self._get_top_issues(all_vulnerabilities),
            'recommendations': self._generate_recommendations(results_by_language),
            
            'success': True
        }
    
    def _get_top_issues(self, vulnerabilities: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top N most critical vulnerabilities."""
        
        # Filter critical and high severity
        critical = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        high = [v for v in vulnerabilities if v.get('severity') == 'High']
        
        top = critical[:limit]
        if len(top) < limit:
            top.extend(high[:limit - len(top)])
        
        return top
    
    def _generate_recommendations(self, results_by_language: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        for language, results in results_by_language.items():
            summary = results['summary']
            
            if summary['critical'] > 0:
                recommendations.append(
                    f"🔴 URGENT: Fix {summary['critical']} critical {language} "
                    f"vulnerabilities immediately"
                )
            
            if summary['high'] > 0:
                recommendations.append(
                    f"⚠️  HIGH PRIORITY: Address {summary['high']} high-severity "
                    f"{language} issues"
                )
            
            # Framework-specific recommendations
            frameworks = LanguagePatterns.get_framework_context(language)
            if frameworks:
                recommendations.append(
                    f"📚 Review {language} code using {frameworks[0]} best practices"
                )
        
        if not recommendations:
            recommendations.append("✅ No critical issues found. Continue regular security reviews.")
        
        return recommendations
    
    async def scan_file(
        self,
        filepath: str,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scan a single file.
        
        Args:
            filepath: Path to file
            language: Optional language override (auto-detected if None)
            
        Returns:
            Scan results for the file
        """
        # Detect language if not provided
        if not language:
            language, confidence = self.detector.detect_from_file(filepath)
            
            if not self.detector.is_supported(language):
                return {
                    'success': False,
                    'error': f'Unsupported language: {language}'
                }
        
        # Read file
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            return {
                'success': False,
                'error': f'Could not read file: {e}'
            }
        
        # Analyze
        result = await self._analyze_file(
            filepath=filepath,
            code=code,
            language=language
        )
        
        result['success'] = True
        result['language'] = language
        result['file'] = filepath
        
        return result
