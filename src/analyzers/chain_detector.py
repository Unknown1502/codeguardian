"""
Vulnerability Chain Detector
Finds complex multi-file attack paths that simple scanners miss
This showcases Gemini 3's ability to reason across entire codebases
"""

import asyncio
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict

from src.core.gemini_client import GeminiClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class VulnerabilityChainDetector:
    """
    Detects multi-step attack chains that span multiple files.
    
    Example chains:
    1. Auth bypass + Privilege escalation = Admin takeover
    2. Path traversal + File upload = Remote code execution
    3. XSS + CSRF = Account hijacking
    
    This is what separates autonomous agents from simple scanners!
    """
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize chain detector.
        
        Args:
            gemini_client: Configured Gemini client
        """
        self.gemini_client = gemini_client
        self.chains = []
    
    async def detect_chains(
        self,
        vulnerabilities: List[Dict[str, Any]],
        analysis_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Detect multi-file vulnerability chains.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            analysis_result: Full codebase analysis
            
        Returns:
            List of detected attack chains
        """
        logger.info("Analyzing vulnerability chains...")
        
        # Group vulnerabilities by file
        vuln_by_file = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_by_file[vuln['file']].append(vuln)
        
        # Find potential chains
        potential_chains = await self._find_potential_chains(
            vulnerabilities,
            analysis_result
        )
        
        # Validate chains with Gemini's reasoning
        validated_chains = []
        for chain in potential_chains:
            is_valid = await self._validate_chain(chain, analysis_result)
            if is_valid:
                validated_chains.append(chain)
        
        self.chains = validated_chains
        logger.info(f"Found {len(validated_chains)} exploitable attack chains")
        
        return validated_chains
    
    async def _find_potential_chains(
        self,
        vulnerabilities: List[Dict[str, Any]],
        analysis_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find potential multi-step attack chains."""
        
        chains = []
        
        # Known dangerous combinations
        chain_patterns = [
            {
                'name': 'Authentication Bypass → Privilege Escalation',
                'types': ['broken-auth', 'broken-access-control'],
                'severity': 'critical',
                'description': 'Attacker bypasses auth then escalates to admin'
            },
            {
                'name': 'XSS → Session Hijacking',
                'types': ['xss', 'sensitive-data-exposure'],
                'severity': 'critical',
                'description': 'XSS steals session token, hijacks account'
            },
            {
                'name': 'Path Traversal → File Upload RCE',
                'types': ['path-traversal', 'security-misconfiguration'],
                'severity': 'critical',
                'description': 'Upload malicious file then execute via path traversal'
            },
            {
                'name': 'SQL Injection → Data Exfiltration',
                'types': ['sql-injection', 'sensitive-data-exposure'],
                'severity': 'critical',
                'description': 'Extract sensitive data through SQL injection'
            },
            {
                'name': 'Command Injection → System Takeover',
                'types': ['command-injection', 'broken-access-control'],
                'severity': 'critical',
                'description': 'Execute commands to gain system access'
            }
        ]
        
        # Check for each pattern
        for pattern in chain_patterns:
            matching_vulns = self._find_matching_vulnerabilities(
                vulnerabilities,
                pattern['types']
            )
            
            if len(matching_vulns) >= 2:
                # Potential chain found!
                chain = {
                    'id': f"CHAIN-{len(chains) + 1:03d}",
                    'name': pattern['name'],
                    'severity': pattern['severity'],
                    'description': pattern['description'],
                    'vulnerabilities': matching_vulns,
                    'steps': len(matching_vulns),
                    'validated': False
                }
                chains.append(chain)
        
        return chains
    
    def _find_matching_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        required_types: List[str]
    ) -> List[Dict[str, Any]]:
        """Find vulnerabilities matching the required types."""
        
        matching = []
        for vuln_type in required_types:
            for vuln in vulnerabilities:
                if vuln_type in vuln.get('type', '').lower():
                    matching.append(vuln)
                    break  # Only need one of each type
        
        return matching
    
    async def _validate_chain(
        self,
        chain: Dict[str, Any],
        analysis_result: Dict[str, Any]
    ) -> bool:
        """
        Use Gemini to validate if the chain is actually exploitable.
        
        This is where autonomous reasoning shines - understanding
        complex multi-step attacks across the codebase.
        """
        
        # Build context about the chain
        vuln_details = []
        for vuln in chain['vulnerabilities']:
            vuln_details.append(
                f"- {vuln['type']} in {vuln['file']} (Line {vuln.get('location', {}).get('line', '?')})"
            )
        
        prompt = f"""
You are analyzing a potential multi-step attack chain in a codebase.

CHAIN: {chain['name']}
DESCRIPTION: {chain['description']}

VULNERABILITIES IN CHAIN:
{chr(10).join(vuln_details)}

CODEBASE CONTEXT:
- Total files: {analysis_result.get('files_count', 0)}
- Dependencies: {len(analysis_result.get('dependencies', {}))}
- Data flows: {len(analysis_result.get('data_flows', []))}

QUESTION:
Can these vulnerabilities be chained together to create a working exploit path?
Consider:
1. Are the vulnerable endpoints accessible in sequence?
2. Can output from step 1 be used as input to step 2?
3. Are there any security controls that break the chain?
4. Is this a realistic attack scenario?

Answer with:
VALID: true/false
REASONING: [Your analysis]
CONFIDENCE: [0-100]
EXPLOIT_PATH: [Step-by-step if valid]
"""
        
        try:
            result = await self.gemini_client.analyze_with_extended_reasoning(
                prompt=prompt,
                thinking_level=5  # Maximum reasoning for complex chains
            )
            
            if result['success']:
                conclusion = result.get('conclusion', '').lower()
                
                # Check if Gemini validated the chain
                if 'valid: true' in conclusion or 'is valid' in conclusion:
                    chain['validated'] = True
                    chain['reasoning'] = result.get('thoughts', [])
                    chain['confidence'] = self._extract_confidence(conclusion)
                    
                    logger.info(f"✓ Validated chain: {chain['name']}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Chain validation failed: {e}")
            return False
    
    def _extract_confidence(self, text: str) -> int:
        """Extract confidence score from text."""
        import re
        match = re.search(r'confidence[:\s]+(\d+)', text, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return 75  # Default
    
    def get_critical_chains(self) -> List[Dict[str, Any]]:
        """Get only critical severity chains."""
        return [c for c in self.chains if c.get('severity') == 'critical']
    
    def generate_chain_report(self) -> str:
        """Generate human-readable report of attack chains."""
        
        if not self.chains:
            return "No multi-step attack chains detected."
        
        lines = []
        lines.append("=" * 70)
        lines.append("MULTI-STEP ATTACK CHAINS")
        lines.append("=" * 70)
        lines.append("")
        
        for chain in self.chains:
            lines.append(f"🔗 {chain['name']}")
            lines.append(f"   Severity: {chain['severity'].upper()}")
            lines.append(f"   Description: {chain['description']}")
            lines.append(f"   Steps: {chain['steps']}")
            lines.append(f"   Validated: {'✓ Yes' if chain['validated'] else '✗ No'}")
            
            if chain.get('confidence'):
                lines.append(f"   Confidence: {chain['confidence']}%")
            
            lines.append("\n   Attack Path:")
            for i, vuln in enumerate(chain['vulnerabilities'], 1):
                lines.append(f"     {i}. {vuln['type']} in {vuln['file']}")
            
            lines.append("")
        
        return "\n".join(lines)
