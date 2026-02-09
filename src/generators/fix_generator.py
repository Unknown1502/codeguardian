"""
Fix Generator
Automatically generates security patches and tests them
Uses Gemini 3's code generation and reasoning capabilities
"""

import asyncio
from typing import Dict, List, Any
from datetime import datetime

from src.core.gemini_client import GeminiClient
from src.core.marathon_agent import MarathonAgent
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class FixGenerator:
    """
    Autonomous fix generator for security vulnerabilities.
    Generates patches, tests them, and iterates until tests pass.
    """
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize fix generator.
        
        Args:
            gemini_client: Configured Gemini client
        """
        self.gemini_client = gemini_client
        self.fixes = []
    
    async def generate_and_test_fixes(
        self,
        vulnerabilities: List[Dict[str, Any]],
        analysis_result: Dict[str, Any],
        marathon_agent: MarathonAgent,
        max_iterations: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate and test fixes for all vulnerabilities.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            analysis_result: Codebase analysis result
            marathon_agent: Marathon agent for orchestration
            max_iterations: Maximum fix iteration attempts per vulnerability
            
        Returns:
            List of generated fixes with test results
        """
        logger.info(f"Generating fixes for {len(vulnerabilities)} vulnerabilities")
        
        # Prioritize critical and high severity
        priority_vulns = [
            v for v in vulnerabilities 
            if v.get('severity') in ['critical', 'high']
        ]
        
        # Limit to top vulnerabilities for demo
        vulns_to_fix = priority_vulns[:10] if priority_vulns else vulnerabilities[:10]
        
        # Generate fixes with controlled concurrency
        fix_tasks = []
        for vuln in vulns_to_fix:
            task = self._generate_fix_with_retry(
                vuln,
                analysis_result,
                marathon_agent,
                max_iterations
            )
            fix_tasks.append(task)
        
        # Execute in small batches to avoid rate limits
        results = []
        for i in range(0, len(fix_tasks), 3):
            batch = fix_tasks[i:i+3]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend([r for r in batch_results if isinstance(r, dict)])
            
            # Small delay between batches
            if i + 3 < len(fix_tasks):
                await asyncio.sleep(2)
        
        self.fixes = results
        
        logger.info(f"Generated {len(self.fixes)} fixes")
        logger.info(f"Passing tests: {sum(1 for f in self.fixes if f.get('tests_pass', False))}")
        
        return self.fixes
    
    async def _generate_fix_with_retry(
        self,
        vulnerability: Dict[str, Any],
        analysis_result: Dict[str, Any],
        marathon_agent: MarathonAgent,
        max_iterations: int
    ) -> Dict[str, Any]:
        """
        Generate fix with iterative testing and refinement.
        
        Uses self-correction: if tests fail, analyze why and regenerate.
        """
        
        logger.info(f"Generating fix for {vulnerability['id']}: {vulnerability['type']}")
        
        # Read original code
        from pathlib import Path
        root_path = Path(analysis_result['root_path'])
        file_path = root_path / vulnerability['file']
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                original_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return {
                'vulnerability_id': vulnerability['id'],
                'success': False,
                'error': f"Could not read file: {e}"
            }
        
        # Iterative fix generation
        for iteration in range(max_iterations):
            logger.debug(f"Fix iteration {iteration + 1}/{max_iterations}")
            
            # Generate fix
            fix_result = await self.gemini_client.generate_security_fix(
                vulnerability=vulnerability,
                original_code=original_code,
                test_suite=None  # TODO: Integrate with test frameworks
            )
            
            if not fix_result['success']:
                logger.warning(f"Fix generation failed: {fix_result.get('error')}")
                continue
            
            # Extract fixed code
            fixed_code = self._extract_fixed_code(fix_result)
            
            if not fixed_code:
                logger.warning("Could not extract fixed code from response")
                continue
            
            # Test the fix
            test_result = await self._test_fix(
                original_code=original_code,
                fixed_code=fixed_code,
                file_path=vulnerability['file']
            )
            
            if test_result['passed']:
                # Success!
                logger.info(f"✓ Fix validated for {vulnerability['id']}")
                
                return {
                    'vulnerability_id': vulnerability['id'],
                    'vulnerability_type': vulnerability['type'],
                    'file': vulnerability['file'],
                    'original_code': original_code,
                    'fixed_code': fixed_code,
                    'tests_pass': True,
                    'iterations': iteration + 1,
                    'explanation': fix_result.get('conclusion', ''),
                    'test_results': test_result,
                    'generated_at': datetime.now().isoformat(),
                    'success': True
                }
            else:
                # Test failed, prepare for retry
                logger.debug(f"Tests failed: {test_result.get('error')}")
                
                # Update vulnerability with test feedback for next iteration
                vulnerability['test_feedback'] = test_result.get('error', 'Tests did not pass')
        
        # Max iterations reached without success
        return {
            'vulnerability_id': vulnerability['id'],
            'vulnerability_type': vulnerability['type'],
            'file': vulnerability['file'],
            'tests_pass': False,
            'iterations': max_iterations,
            'error': 'Could not generate passing fix within iteration limit',
            'success': False
        }
    
    def _extract_fixed_code(self, fix_result: Dict[str, Any]) -> str:
        """Extract fixed code from Gemini response."""
        
        # Try structured data first
        if fix_result.get('structured_data'):
            data = fix_result['structured_data']
            if isinstance(data, dict) and 'fixed_code' in data:
                return data['fixed_code']
        
        # Try to extract from raw text
        raw_text = fix_result.get('conclusion', fix_result.get('raw_text', ''))
        
        # Look for code blocks
        if '```' in raw_text:
            # Extract first code block
            parts = raw_text.split('```')
            if len(parts) >= 3:
                code_block = parts[1]
                # Remove language identifier if present
                lines = code_block.split('\n')
                if lines[0].strip() in ['python', 'javascript', 'java', 'js', 'py']:
                    code_block = '\n'.join(lines[1:])
                return code_block.strip()
        
        # If no code block, try to extract from FIXED CODE: section
        if 'FIXED CODE:' in raw_text.upper():
            parts = raw_text.upper().split('FIXED CODE:')
            if len(parts) >= 2:
                return parts[1].strip()
        
        return ""
    
    async def _test_fix(
        self,
        original_code: str,
        fixed_code: str,
        file_path: str
    ) -> Dict[str, Any]:
        """
        Test if the fixed code passes basic validation.
        
        In production, this would:
        1. Run actual test suite
        2. Check for regressions
        3. Verify security fix effectiveness
        
        For demo, we do basic validation.
        """
        
        try:
            # Basic validation: syntax check
            if file_path.endswith('.py'):
                import ast
                try:
                    ast.parse(fixed_code)
                    syntax_valid = True
                except SyntaxError as e:
                    syntax_valid = False
                    return {
                        'passed': False,
                        'error': f'Syntax error: {str(e)}'
                    }
            else:
                syntax_valid = True
            
            # Check if fix actually changed something
            if original_code.strip() == fixed_code.strip():
                return {
                    'passed': False,
                    'error': 'Fixed code is identical to original'
                }
            
            # Basic heuristic: fixed code should be similar length
            # (within 50% of original)
            len_ratio = len(fixed_code) / max(len(original_code), 1)
            if len_ratio < 0.5 or len_ratio > 2.0:
                return {
                    'passed': False,
                    'error': f'Fixed code length suspicious: {len_ratio:.2f}x original'
                }
            
            # All basic checks passed
            return {
                'passed': True,
                'syntax_valid': syntax_valid,
                'length_ratio': len_ratio,
                'message': 'Basic validation passed'
            }
            
        except Exception as e:
            return {
                'passed': False,
                'error': f'Test error: {str(e)}'
            }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get fix generation summary."""
        
        total = len(self.fixes)
        passing = sum(1 for f in self.fixes if f.get('tests_pass', False))
        failed = total - passing
        
        avg_iterations = sum(f.get('iterations', 0) for f in self.fixes) / max(total, 1)
        
        return {
            'total_fixes': total,
            'passing': passing,
            'failed': failed,
            'success_rate': (passing / max(total, 1)) * 100,
            'average_iterations': avg_iterations
        }
