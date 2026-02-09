"""
Red Team Agent - Offensive Security AI
Generates creative exploits and attack vectors using Gemini 3
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.core.gemini_client import GeminiClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class RedTeamAgent:
    """
    AI Red Team - Offensive security testing agent.
    
    Capabilities:
    - Generate creative exploit payloads
    - Find novel attack vectors
    - Chain vulnerabilities for maximum impact
    - Bypass security controls
    """
    
    def __init__(self, gemini_client: GeminiClient):
        """
        Initialize Red Team agent.
        
        Args:
            gemini_client: Configured Gemini 3 client
        """
        self.gemini_client = gemini_client
        self.attack_history = []
        self.exploit_count = 0
        
    async def analyze_target(
        self,
        code: str,
        language: str = 'python',
        previous_defenses: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Analyze code from offensive perspective.
        
        Args:
            code: Target code to analyze
            language: Programming language
            previous_defenses: Previous defensive measures to bypass
            
        Returns:
            Dict with attack_vectors, exploits, and reasoning
        """
        logger.info(f"[RED TEAM] Analyzing target (round {len(self.attack_history) + 1})")
        
        defense_context = ""
        if previous_defenses:
            defense_context = f"""
Previous defensive measures attempted:
{self._format_defenses(previous_defenses)}

Your mission: Find weaknesses in these defenses and generate bypasses.
"""
        
        prompt = f"""You are an elite Red Team security researcher. Your goal is to find vulnerabilities 
and create working exploits.

{defense_context}

Target Code ({language}):
```{language}
{code}
```

As an attacker, provide:

1. **Attack Surface Analysis**: What can an attacker control? (inputs, files, network, environment)
2. **Vulnerability Identification**: Find exploitable weaknesses
3. **Exploit Development**: Create working proof-of-concept exploits
4. **Attack Chain**: How to chain multiple vulnerabilities for maximum impact
5. **Bypass Techniques**: How to evade detection and defensive controls

Return JSON:
{{
    "attack_surface": ["..."],
    "vulnerabilities": [
        {{
            "type": "SQL Injection",
            "severity": "Critical",
            "line": 15,
            "attack_vector": "user input via login form",
            "exploit_payload": "' OR '1'='1' -- ",
            "impact": "Full database access, authentication bypass",
            "confidence": 95
        }}
    ],
    "attack_chains": [
        {{
            "name": "Full System Compromise",
            "steps": ["1. SQL injection", "2. Extract admin hash", "3. Crack password", "4. Privilege escalation"],
            "severity": "Critical"
        }}
    ],
    "bypass_techniques": ["..."],
    "reasoning": "Detailed offensive analysis..."
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=5  # Maximum reasoning for complex attacks
        )
        
        attack_record = {
            'timestamp': datetime.now().isoformat(),
            'round': len(self.attack_history) + 1,
            'result': result,
            'had_defenses': bool(previous_defenses)
        }
        
        self.attack_history.append(attack_record)
        
        if result.get('success'):
            vulnerabilities = result.get('vulnerabilities', [])
            self.exploit_count += len(vulnerabilities)
            logger.info(f"[RED TEAM] Found {len(vulnerabilities)} vulnerabilities")
        
        return result
    
    async def generate_advanced_exploit(
        self,
        vulnerability: Dict[str, Any],
        code: str,
        language: str = 'python'
    ) -> Dict[str, Any]:
        """
        Generate sophisticated exploit for a specific vulnerability.
        
        Args:
            vulnerability: Vulnerability details
            code: Vulnerable code
            language: Programming language
            
        Returns:
            Detailed exploit with payload, steps, and validation
        """
        logger.info(f"[RED TEAM] Crafting exploit for {vulnerability.get('type', 'unknown')}")
        
        prompt = f"""You are creating a weaponized exploit for penetration testing.

Vulnerability:
Type: {vulnerability.get('type')}
Severity: {vulnerability.get('severity')}
Line: {vulnerability.get('line')}
Description: {vulnerability.get('explanation', vulnerability.get('attack_vector', 'N/A'))}

Target Code:
```{language}
{code}
```

Create a professional penetration testing exploit with:

1. **Exploit Payload**: Actual code/input to trigger the vulnerability
2. **Delivery Method**: How to deliver the exploit (HTTP request, file upload, etc.)
3. **Validation**: How to verify successful exploitation
4. **Escalation**: How to escalate privileges after initial exploit
5. **Persistence**: How to maintain access

Return JSON:
{{
    "exploit_name": "descriptive name",
    "payload": "actual exploit code/input",
    "delivery_method": "HTTP POST to /login",
    "steps": ["1. ...", "2. ...", "3. ..."],
    "validation": "how to verify success",
    "escalation_path": "next steps after initial exploit",
    "risk_level": "Critical/High/Medium",
    "difficulty": "Trivial/Easy/Medium/Hard/Expert",
    "tools_required": ["curl", "sqlmap", "..."],
    "sample_request": "full HTTP request or command",
    "expected_response": "what success looks like"
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=4
        )
        
        return result
    
    async def find_bypass(
        self,
        defense_mechanism: str,
        code: str,
        language: str = 'python'
    ) -> Dict[str, Any]:
        """
        Find bypass techniques for a specific defense.
        
        Args:
            defense_mechanism: Description of defensive measure
            code: Code with defense implemented
            language: Programming language
            
        Returns:
            Bypass techniques and exploits
        """
        logger.info(f"[RED TEAM] Looking for bypass: {defense_mechanism}")
        
        prompt = f"""You are bypassing a security control. Think like an attacker.

Defense Mechanism:
{defense_mechanism}

Protected Code:
```{language}
{code}
```

Find bypass techniques:

1. **Weakness Analysis**: What are the limitations of this defense?
2. **Bypass Techniques**: How can an attacker circumvent it?
3. **Proof-of-Concept**: Working bypass example
4. **Alternative Attacks**: Different attack vectors if bypass fails

Return JSON:
{{
    "defense_weaknesses": ["...", "..."],
    "bypass_techniques": [
        {{
            "method": "encoding bypass",
            "payload": "specific payload",
            "success_probability": 80,
            "explanation": "..."
        }}
    ],
    "alternative_vectors": ["...", "..."],
    "recommended_improvements": "how to fix the defense"
}}
"""
        
        result = await self.gemini_client.analyze_with_extended_reasoning(
            prompt=prompt,
            thinking_level=5
        )
        
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Red Team attack statistics."""
        return {
            'total_rounds': len(self.attack_history),
            'total_exploits': self.exploit_count,
            'attack_history': self.attack_history
        }
    
    def _format_defenses(self, defenses: List[Dict[str, Any]]) -> str:
        """Format defense list for prompt."""
        formatted = []
        for i, defense in enumerate(defenses, 1):
            formatted.append(f"{i}. {defense.get('type', 'Unknown')} - {defense.get('description', 'N/A')}")
        return "\n".join(formatted)
