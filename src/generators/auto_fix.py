"""
Automatic Fix Generator with Diff Visualization
Applies security fixes to actual code files and generates professional diffs
"""

import difflib
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
import json
import re

from src.core.gemini_client import GeminiClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class AutoFixGenerator:
    """
    Automatically generate and apply security fixes with git-style diff visualization.
    """
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize auto-fix generator.
        
        Args:
            gemini_client: Configured Gemini client for fix generation
        """
        self.gemini_client = gemini_client
        self.fixes_generated = []
        self.diffs = []
    
    async def generate_fix(
        self,
        original_code: str,
        vulnerability: Dict[str, Any],
        language: str = 'python',
        stream_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Generate a fix for a specific vulnerability.
        
        Args:
            original_code: Original vulnerable code
            vulnerability: Vulnerability details
            language: Programming language
            stream_callback: Optional callback for streaming progress
            
        Returns:
            Fix result with patched code and explanation
        """
        logger.info(f"Generating fix for {vulnerability.get('type', 'Unknown')} vulnerability")
        
        vuln_type = vulnerability.get('type', 'Unknown')
        vuln_line = vulnerability.get('line', 'Unknown')
        vuln_explanation = vulnerability.get('explanation', 'No details')
        
        prompt = f"""You are a security expert. Fix the following vulnerability:

Vulnerability Type: {vuln_type}
Affected Line: {vuln_line}
Issue: {vuln_explanation}

Original Code:
```{language}
{original_code}
```

Requirements:
1. Generate ONLY the fixed code (complete file, not just the changed section)
2. Apply security best practices
3. Maintain functionality while removing vulnerability
4. Add comments explaining the security fix

Respond with JSON:
{{
    "fixed_code": "complete fixed code here",
    "changes_made": ["list of specific changes"],
    "security_rationale": "why this fix is secure"
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=4,
            stream=bool(stream_callback),
            stream_callback=stream_callback
        )
        
        if not result.get('success'):
            logger.error(f"Fix generation failed: {result.get('error')}")
            return {'success': False, 'error': result.get('error')}
        
        structured_data = result.get('structured_data', {})
        fixed_code = structured_data.get('fixed_code', '')
        
        if not fixed_code:
            # Try to extract code from response text
            response_text = result.get('response', '')
            fixed_code = self._extract_code_from_response(response_text, language)
        
        if not fixed_code:
            logger.error("Could not extract fixed code from response")
            return {'success': False, 'error': 'No fixed code generated'}
        
        # Generate diff
        diff = self.generate_diff(original_code, fixed_code, vulnerability.get('file_path', 'code'))
        
        fix_result = {
            'success': True,
            'vulnerability_type': vuln_type,
            'original_code': original_code,
            'fixed_code': fixed_code,
            'changes_made': structured_data.get('changes_made', []),
            'security_rationale': structured_data.get('security_rationale', ''),
            'diff': diff,
            'timestamp': datetime.now().isoformat()
        }
        
        self.fixes_generated.append(fix_result)
        self.diffs.append(diff)
        
        logger.info(f"Successfully generated fix for {vuln_type}")
        return fix_result
    
    def generate_diff(
        self,
        original_code: str,
        fixed_code: str,
        file_path: str = 'code'
    ) -> Dict[str, Any]:
        """
        Generate git-style diff between original and fixed code.
        
        Args:
            original_code: Original code
            fixed_code: Fixed code
            file_path: File path for display
            
        Returns:
            Diff information with unified diff format
        """
        original_lines = original_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)
        
        # Generate unified diff
        diff_lines = list(difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f'a/{file_path}',
            tofile=f'b/{file_path}',
            lineterm=''
        ))
        
        # Parse diff for statistics
        additions = sum(1 for line in diff_lines if line.startswith('+') and not line.startswith('+++'))
        deletions = sum(1 for line in diff_lines if line.startswith('-') and not line.startswith('---'))
        
        # Extract changed hunks
        hunks = self._parse_hunks(diff_lines)
        
        return {
            'file_path': file_path,
            'unified_diff': ''.join(diff_lines),
            'additions': additions,
            'deletions': deletions,
            'hunks': hunks,
            'summary': f"+{additions} -{deletions}"
        }
    
    def _parse_hunks(self, diff_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse diff into individual hunks."""
        hunks = []
        current_hunk = None
        
        for line in diff_lines:
            if line.startswith('@@'):
                if current_hunk:
                    hunks.append(current_hunk)
                
                # Parse hunk header: @@ -1,5 +1,6 @@
                match = re.match(r'@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@', line)
                if match:
                    current_hunk = {
                        'header': line,
                        'old_start': int(match.group(1)),
                        'old_count': int(match.group(2)) if match.group(2) else 1,
                        'new_start': int(match.group(3)),
                        'new_count': int(match.group(4)) if match.group(4) else 1,
                        'lines': []
                    }
            elif current_hunk is not None:
                if line.startswith(('---', '+++')):
                    continue
                current_hunk['lines'].append(line)
        
        if current_hunk:
            hunks.append(current_hunk)
        
        return hunks
    
    def _extract_code_from_response(self, response_text: str, language: str) -> str:
        """Extract code from markdown code blocks in response."""
        # Try language-specific code block
        pattern = f'```{language}\\s*\\n(.*?)```'
        match = re.search(pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Try generic code block
        pattern = '```\\s*\\n(.*?)```'
        match = re.search(pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        return ''
    
    def format_diff_for_display(self, diff: Dict[str, Any], use_color: bool = True) -> str:
        """
        Format diff for terminal display with optional color coding.
        
        Args:
            diff: Diff dictionary from generate_diff()
            use_color: Whether to include ANSI color codes
            
        Returns:
            Formatted diff string
        """
        lines = []
        
        # Header
        lines.append(f"File: {diff['file_path']}")
        lines.append(f"Changes: {diff['summary']}")
        lines.append("=" * 80)
        
        # Display hunks
        for hunk in diff['hunks']:
            lines.append(hunk['header'])
            
            for line in hunk['lines']:
                if use_color:
                    if line.startswith('+'):
                        lines.append(f"\033[32m{line}\033[0m")  # Green
                    elif line.startswith('-'):
                        lines.append(f"\033[31m{line}\033[0m")  # Red
                    else:
                        lines.append(line)
                else:
                    lines.append(line)
        
        return '\n'.join(lines)
    
    async def apply_fix_to_file(
        self,
        file_path: Path,
        fixed_code: str,
        create_backup: bool = True
    ) -> Dict[str, Any]:
        """
        Apply fix to actual file on disk.
        
        Args:
            file_path: Path to file to fix
            fixed_code: Fixed code content
            create_backup: Whether to create .backup file
            
        Returns:
            Application result
        """
        logger.info(f"Applying fix to {file_path}")
        
        if not file_path.exists():
            return {'success': False, 'error': f'File not found: {file_path}'}
        
        try:
            # Create backup if requested
            if create_backup:
                backup_path = file_path.with_suffix(file_path.suffix + '.backup')
                backup_path.write_text(file_path.read_text(), encoding='utf-8')
                logger.info(f"Created backup: {backup_path}")
            
            # Write fixed code
            file_path.write_text(fixed_code, encoding='utf-8')
            logger.info(f"Successfully applied fix to {file_path}")
            
            return {
                'success': True,
                'file_path': str(file_path),
                'backup_path': str(backup_path) if create_backup else None,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to apply fix: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_commit_message(self, fixes: List[Dict[str, Any]]) -> str:
        """
        Generate professional git commit message for fixes.
        
        Args:
            fixes: List of fix results
            
        Returns:
            Formatted commit message
        """
        if not fixes:
            return "fix: Apply security patches"
        
        vuln_types = list(set(fix.get('vulnerability_type', 'Unknown') for fix in fixes))
        
        # Commit message format
        lines = ["fix: Apply security patches for multiple vulnerabilities", ""]
        
        for fix in fixes:
            vuln_type = fix.get('vulnerability_type', 'Unknown')
            changes = fix.get('changes_made', [])
            
            lines.append(f"- Fix {vuln_type}")
            for change in changes[:2]:  # Limit to 2 changes per fix
                lines.append(f"  * {change}")
        
        lines.append("")
        lines.append(f"Security patches applied: {len(fixes)}")
        lines.append(f"Vulnerability types addressed: {', '.join(vuln_types)}")
        
        return '\n'.join(lines)
    
    def export_fixes_report(self, output_path: Path) -> Dict[str, Any]:
        """
        Export all fixes to a JSON report.
        
        Args:
            output_path: Path for report file
            
        Returns:
            Export result
        """
        try:
            report = {
                'generated_at': datetime.now().isoformat(),
                'total_fixes': len(self.fixes_generated),
                'fixes': self.fixes_generated
            }
            
            output_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
            logger.info(f"Exported fixes report to {output_path}")
            
            return {'success': True, 'report_path': str(output_path)}
        
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return {'success': False, 'error': str(e)}
