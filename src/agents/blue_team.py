"""
Blue Team Agent - Defensive Security AI
Defends against Red Team attacks and implements security controls using Gemini 3
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.core.gemini_client import GeminiClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class BlueTeamAgent:
    """
    AI Blue Team - Defensive security agent.
    
    Capabilities:
    - Implement security controls
    - Patch vulnerabilities
    - Detect and prevent attacks
    - Strengthen defenses iteratively
    """
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize Blue Team agent.
        
        Args:
            gemini_client: Configured Gemini 3 client
        """
        self.gemini_client = gemini_client
        self.defense_history = []
        self.patches_applied = 0
        
    async def defend_against_attacks(
        self,
        code: str,
        red_team_findings: Dict[str, Any],
        language: str = 'python',
        previous_patches: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Implement defenses against Red Team attacks.
        
        Args:
            code: Code to defend
            red_team_findings: Red Team's attack analysis
            language: Programming language
            previous_patches: Previously applied patches
            
        Returns:
            Dict with patched_code, defenses_added, and reasoning
        """
        logger.info(f"[BLUE TEAM] Defending (round {len(self.defense_history) + 1})")
        
        vulnerabilities = red_team_findings.get('vulnerabilities', [])
        attack_chains = red_team_findings.get('attack_chains', [])
        
        previous_patch_context = ""
        if previous_patches:
            previous_patch_context = f"""
Previous patches applied (that may have been bypassed):
{self._format_patches(previous_patches)}

Strengthen these defenses and add additional layers.
"""
        
        prompt = f"""You are an elite Blue Team security engineer. Your goal is to defend against attacks 
and implement robust security controls.

{previous_patch_context}

Red Team Found {len(vulnerabilities)} Vulnerabilities:
{self._format_vulnerabilities(vulnerabilities)}

Attack Chains Identified:
{self._format_attack_chains(attack_chains)}

Current Code ({language}):
```{language}
{code}
```

As a defender, provide:

1. **Threat Assessment**: Prioritize vulnerabilities by risk
2. **Defense Strategy**: Overall security approach (defense in depth, least privilege, etc.)
3. **Security Patches**: Specific code fixes for each vulnerability
4. **Additional Controls**: Security measures beyond fixes (WAF rules, rate limiting, etc.)
5. **Detection**: How to detect exploitation attempts
6. **Validation**: How to verify defenses are effective

Return JSON:
{{
    "threat_assessment": {{
        "critical_threats": ["..."],
        "priority_order": [1, 3, 2, ...]
    }},
    "defense_strategy": "description of overall approach",
    "patches": [
        {{
            "vulnerability_type": "SQL Injection",
            "line": 15,
            "original_code": "...",
            "patched_code": "...",
            "defense_mechanism": "parameterized queries",
            "additional_controls": ["input validation", "WAF rule"],
            "confidence": 95
        }}
    ],
    "detection_rules": [
        {{
            "type": "SQL injection attempt",
            "pattern": "regex or signature",
            "action": "block and alert"
        }}
    ],
    "security_enhancements": ["enable HTTPS", "implement CSP", "..."],
    "patched_code": "full code with all patches applied",
    "reasoning": "Detailed defensive analysis..."
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=5  # Maximum reasoning for comprehensive defense
        )
        
        defense_record = {
            'timestamp': datetime.now().isoformat(),
            'round': len(self.defense_history) + 1,
            'vulnerabilities_addressed': len(vulnerabilities),
            'result': result
        }
        
        self.defense_history.append(defense_record)
        
        if result.get('success'):
            patches = result.get('patches', [])
            self.patches_applied += len(patches)
            logger.info(f"[BLUE TEAM] Applied {len(patches)} patches")
        
        return result
    
    async def implement_security_control(
        self,
        control_type: str,
        code: str,
        language: str = 'python',
        requirements: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Implement a specific security control.
        
        Args:
            control_type: Type of control (authentication, authorization, encryption, etc.)
            code: Code to secure
            language: Programming language
            requirements: Specific requirements for the control
            
        Returns:
            Implementation details and modified code
        """
        logger.info(f"[BLUE TEAM] Implementing {control_type}")
        
        req_str = ""
        if requirements:
            req_str = f"\nRequirements: {requirements}"
        
        prompt = f"""Implement enterprise-grade {control_type} security control.

{req_str}

Current Code:
```{language}
{code}
```

Provide:

1. **Implementation**: Production-ready code with security control
2. **Configuration**: Required settings and dependencies
3. **Best Practices**: Industry standards being followed
4. **Testing**: How to verify the control works
5. **Monitoring**: How to monitor effectiveness

Return JSON:
{{
    "control_type": "{control_type}",
    "implementation": "full code with control implemented",
    "dependencies": ["library1", "library2"],
    "configuration": {{"setting": "value"}},
    "best_practices_applied": ["OWASP guidelines", "..."],
    "test_cases": ["test1", "test2"],
    "monitoring_metrics": ["failed_auth_attempts", "..."],
    "documentation": "how to use and maintain this control"
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=4
        )
        
        return result
    
    async def validate_defense(
        self,
        original_code: str,
        patched_code: str,
        vulnerability: Dict[str, Any],
        language: str = 'python'
    ) -> Dict[str, Any]:
        """
        Validate that a defense actually works.
        
        Args:
            original_code: Original vulnerable code
            patched_code: Code with defense applied
            vulnerability: Vulnerability details
            language: Programming language
            
        Returns:
            Validation results with effectiveness score
        """
        logger.info(f"[BLUE TEAM] Validating defense for {vulnerability.get('type')}")
        
        prompt = f"""Validate that this security patch effectively prevents the vulnerability.

Vulnerability:
Type: {vulnerability.get('type')}
Severity: {vulnerability.get('severity')}
Original Exploit: {vulnerability.get('exploit_payload', 'N/A')}

Original Vulnerable Code:
```{language}
{original_code}
```

Patched Code:
```{language}
{patched_code}
```

Analyze:

1. **Effectiveness**: Does the patch actually prevent the exploit?
2. **Edge Cases**: Are there bypasses or edge cases?
3. **Completeness**: Are all attack vectors covered?
4. **Side Effects**: Does the patch break functionality?
5. **Best Practices**: Does it follow security standards?

Return JSON:
{{
    "is_effective": true/false,
    "effectiveness_score": 0-100,
    "strengths": ["...", "..."],
    "weaknesses": ["...", "..."],
    "bypass_possibilities": ["...", "..."],
    "improvement_suggestions": ["...", "..."],
    "test_results": {{
        "original_exploit_blocked": true/false,
        "edge_cases_tested": ["..."],
        "false_positives": []
    }},
    "recommendation": "Accept/Improve/Reject"
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=4
        )
        
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Blue Team defense statistics."""
        return {
            'total_rounds': len(self.defense_history),
            'total_patches': self.patches_applied,
            'defense_history': self.defense_history
        }
    
    def _format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerability list for prompt."""
        if not vulnerabilities:
            return "None found"
        
        formatted = []
        for i, vuln in enumerate(vulnerabilities, 1):
            formatted.append(
                f"{i}. {vuln.get('type', 'Unknown')} (Line {vuln.get('line', '?')}) - "
                f"Severity: {vuln.get('severity', 'Unknown')}\n"
                f"   Exploit: {vuln.get('exploit_payload', 'N/A')}"
            )
        return "\n".join(formatted)
    
    def _format_attack_chains(self, chains: List[Dict[str, Any]]) -> str:
        """Format attack chain list for prompt."""
        if not chains:
            return "None identified"
        
        formatted = []
        for i, chain in enumerate(chains, 1):
            steps = " → ".join(chain.get('steps', []))
            formatted.append(f"{i}. {chain.get('name', 'Unknown')}: {steps}")
        return "\n".join(formatted)
    
    def _format_patches(self, patches: List[str]) -> str:
        """Format patch list for prompt."""
        return "\n".join(f"- {patch}" for patch in patches)
