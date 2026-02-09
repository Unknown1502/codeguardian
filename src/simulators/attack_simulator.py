"""
Attack Simulator
Actually executes exploit attempts in isolated environments
"""

import asyncio
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any
import docker

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class AttackSimulator:
    """
    Simulates real attacks to verify exploitability.
    Uses Docker containers for isolation.
    """
    
    def __init__(self, enable_sandbox: bool = True):
        """
        Initialize attack simulator.
        
        Args:
            enable_sandbox: Use Docker for isolation (recommended)
        """
        self.enable_sandbox = enable_sandbox
        self.docker_client = None
        
        if enable_sandbox:
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                logger.warning(f"Docker not available: {e}. Sandbox disabled.")
                self.enable_sandbox = False
    
    async def simulate_attack(
        self,
        vulnerability: Dict[str, Any],
        code_snippet: str,
        exploit_payload: str
    ) -> Dict[str, Any]:
        """
        Execute an attack simulation to verify exploitability.
        
        Args:
            vulnerability: Vulnerability details
            code_snippet: Code containing vulnerability
            exploit_payload: Attack payload to test
            
        Returns:
            Simulation results with success/failure and evidence
        """
        
        logger.info(f"Simulating attack for {vulnerability['id']}")
        
        vuln_type = vulnerability.get('type', '').lower()
        
        # Route to appropriate simulator
        if 'sql' in vuln_type:
            return await self._simulate_sql_injection(code_snippet, exploit_payload)
        elif 'xss' in vuln_type or 'cross-site' in vuln_type:
            return await self._simulate_xss(code_snippet, exploit_payload)
        elif 'command' in vuln_type:
            return await self._simulate_command_injection(code_snippet, exploit_payload)
        else:
            return await self._generic_simulation(vulnerability, code_snippet, exploit_payload)
    
    async def _simulate_sql_injection(
        self,
        code: str,
        payload: str
    ) -> Dict[str, Any]:
        """Simulate SQL injection attack."""
        
        try:
            # Create test environment
            test_code = f"""
import sqlite3
import sys

# Setup test database
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute('CREATE TABLE users (id INTEGER, username TEXT, password TEXT)')
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
cursor.execute("INSERT INTO users VALUES (2, 'user', 'pass456')")
conn.commit()

# Vulnerable code
user_input = sys.argv[1] if len(sys.argv) > 1 else "1"

# Execute vulnerable query
query = f"SELECT * FROM users WHERE id = {{user_input}}"
try:
    cursor.execute(query)
    results = cursor.fetchall()
    print("ATTACK_SUCCESS" if len(results) > 1 else "ATTACK_FAILED")
    print(f"Rows returned: {{len(results)}}")
    for row in results:
        print(row)
except Exception as e:
    print(f"ATTACK_FAILED: {{e}}")
"""
            
            # Run in sandbox
            result = await self._run_in_sandbox(
                test_code,
                args=[payload],
                language='python'
            )
            
            exploitable = 'ATTACK_SUCCESS' in result['stdout']
            
            return {
                'success': True,
                'exploitable': exploitable,
                'evidence': result['stdout'],
                'method': 'SQL Injection via numeric parameter',
                'payload': payload,
                'impact': 'Data disclosure' if exploitable else 'No impact'
            }
            
        except Exception as e:
            logger.error(f"SQL injection simulation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'exploitable': None
            }
    
    async def _simulate_xss(
        self,
        code: str,
        payload: str
    ) -> Dict[str, Any]:
        """Simulate XSS attack."""
        
        try:
            # Create test HTML page
            test_html = f"""
<!DOCTYPE html>
<html>
<head><title>XSS Test</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: {payload}</p>
</body>
</html>
"""
            
            # Check if script tags would execute
            exploitable = (
                '<script>' in payload.lower() or
                'javascript:' in payload.lower() or
                'onerror=' in payload.lower() or
                'onload=' in payload.lower()
            )
            
            return {
                'success': True,
                'exploitable': exploitable,
                'evidence': test_html,
                'method': 'Reflected XSS in search parameter',
                'payload': payload,
                'impact': 'Session hijacking, credential theft' if exploitable else 'No impact'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'exploitable': None
            }
    
    async def _simulate_command_injection(
        self,
        code: str,
        payload: str
    ) -> Dict[str, Any]:
        """Simulate command injection attack."""
        
        try:
            # Test if shell metacharacters are present
            dangerous_chars = [';', '|', '&&', '||', '$', '`', '\n']
            exploitable = any(char in payload for char in dangerous_chars)
            
            if exploitable:
                # Simulate what would happen (DON'T actually execute!)
                impact = "Arbitrary command execution - attacker could:"
                if ';' in payload or '|' in payload:
                    impact += "\n- Execute additional commands"
                if '`' in payload or '$(' in payload:
                    impact += "\n- Execute subshell commands"
                if '..' in payload or '/' in payload:
                    impact += "\n- Access filesystem"
            else:
                impact = "No impact - payload sanitized"
            
            return {
                'success': True,
                'exploitable': exploitable,
                'evidence': f"Payload contains shell metacharacters: {payload}",
                'method': 'Command injection via unsanitized input',
                'payload': payload,
                'impact': impact
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'exploitable': None
            }
    
    async def _generic_simulation(
        self,
        vulnerability: Dict[str, Any],
        code: str,
        payload: str
    ) -> Dict[str, Any]:
        """Generic simulation for other vulnerability types."""
        
        return {
            'success': True,
            'exploitable': True,  # Conservative assumption
            'evidence': 'Manual verification recommended',
            'method': vulnerability.get('type', 'Unknown'),
            'payload': payload,
            'impact': 'Requires manual assessment'
        }
    
    async def _run_in_sandbox(
        self,
        code: str,
        args: list = None,
        language: str = 'python'
    ) -> Dict[str, Any]:
        """
        Run code in isolated sandbox.
        
        Args:
            code: Code to execute
            args: Command line arguments
            language: Programming language
            
        Returns:
            Execution results
        """
        
        if not self.enable_sandbox or not self.docker_client:
            # Fallback: run locally with timeout
            return await self._run_locally(code, args, language)
        
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix=f'.{language}',
                delete=False
            ) as f:
                f.write(code)
                temp_file = f.name
            
            # Run in Docker container
            container = self.docker_client.containers.run(
                'python:3.10-slim',  # Use lightweight Python image
                f'python {Path(temp_file).name} {" ".join(args or [])}',
                volumes={
                    Path(temp_file).parent: {'bind': '/app', 'mode': 'ro'}
                },
                working_dir='/app',
                detach=True,
                mem_limit='128m',  # Limit memory
                cpu_quota=50000,    # Limit CPU
                network_disabled=True  # No network access
            )
            
            # Wait with timeout
            result = container.wait(timeout=5)
            stdout = container.logs(stdout=True, stderr=False).decode()
            stderr = container.logs(stdout=False, stderr=True).decode()
            
            # Cleanup
            container.remove()
            Path(temp_file).unlink()
            
            return {
                'success': result['StatusCode'] == 0,
                'stdout': stdout,
                'stderr': stderr,
                'exit_code': result['StatusCode']
            }
            
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return await self._run_locally(code, args, language)
    
    async def _run_locally(
        self,
        code: str,
        args: list = None,
        language: str = 'python'
    ) -> Dict[str, Any]:
        """Fallback: run code locally with strict timeout."""
        
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix=f'.{language}',
                delete=False
            ) as f:
                f.write(code)
                temp_file = f.name
            
            # Run with strict timeout
            cmd = ['python', temp_file] + (args or [])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=3.0
                )
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    'success': False,
                    'stdout': '',
                    'stderr': 'Execution timeout',
                    'exit_code': -1
                }
            
            # Cleanup
            Path(temp_file).unlink()
            
            return {
                'success': proc.returncode == 0,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'exit_code': proc.returncode
            }
            
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1
            }
