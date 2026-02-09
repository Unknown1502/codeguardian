"""
Visualization Engine
Generates visual attack flow diagrams and security graphs
Makes the report more compelling for judges and users
"""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import graphviz
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class VisualizationEngine:
    """
    Generate visual representations of security findings.
    - Attack flow diagrams
    - Dependency graphs
    - Severity heatmaps
    """
    
    def __init__(self, output_dir: str = './reports/diagrams'):
        """
        Initialize visualization engine.
        
        Args:
            output_dir: Directory to save generated diagrams
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if not GRAPHVIZ_AVAILABLE:
            logger.warning("Graphviz not available. Diagrams will not be generated.")
    
    def generate_attack_flow(
        self,
        vulnerability: Dict[str, Any],
        filename: str = None
    ) -> Optional[str]:
        """
        Generate visual attack flow diagram for a vulnerability.
        
        Args:
            vulnerability: Vulnerability details
            filename: Optional output filename
            
        Returns:
            Path to generated diagram or None if failed
        """
        
        if not GRAPHVIZ_AVAILABLE:
            return None
        
        try:
            vuln_type = vulnerability.get('type', 'Unknown')
            vuln_id = vulnerability.get('id', 'VULN-000')
            
            # Create graph
            dot = graphviz.Digraph(comment=f'Attack Flow: {vuln_id}')
            dot.attr(rankdir='LR')
            dot.attr('node', shape='box', style='rounded,filled')
            
            # Build attack flow based on vulnerability type
            if 'sql' in vuln_type.lower():
                self._add_sql_injection_flow(dot, vulnerability)
            elif 'xss' in vuln_type.lower():
                self._add_xss_flow(dot, vulnerability)
            elif 'command' in vuln_type.lower():
                self._add_command_injection_flow(dot, vulnerability)
            else:
                self._add_generic_flow(dot, vulnerability)
            
            # Save diagram
            if filename is None:
                filename = f"attack_flow_{vuln_id}"
            
            output_path = self.output_dir / filename
            dot.render(str(output_path), format='png', cleanup=True)
            
            logger.info(f"Generated attack flow diagram: {output_path}.png")
            return f"{output_path}.png"
            
        except Exception as e:
            logger.error(f"Failed to generate attack flow: {e}")
            return None
    
    def _add_sql_injection_flow(
        self,
        dot: 'graphviz.Digraph',
        vulnerability: Dict[str, Any]
    ):
        """Add SQL injection attack flow nodes."""
        
        dot.node('attacker', 'Attacker', fillcolor='#ff6b6b')
        dot.node('input', 'User Input\n(Malicious SQL)', fillcolor='#ffd93d')
        dot.node('app', f"Application\n{vulnerability.get('file', 'Unknown')}", fillcolor='#6bcf7f')
        dot.node('vuln', 'Vulnerable\nSQL Query', fillcolor='#ff6b6b')
        dot.node('db', 'Database', fillcolor='#4ecdc4')
        dot.node('impact', 'Data Leak\n/Modification', fillcolor='#ff0000', fontcolor='white')
        
        dot.edge('attacker', 'input', 'crafts')
        dot.edge('input', 'app', 'submits')
        dot.edge('app', 'vuln', 'no sanitization')
        dot.edge('vuln', 'db', 'executes')
        dot.edge('db', 'impact', 'returns')
        
        # Add exploit info if available
        if vulnerability.get('attack_simulation', {}).get('exploitable'):
            payload = vulnerability['attack_simulation'].get('payload', '')
            dot.node('exploit', f'Exploit:\n{payload[:30]}...', fillcolor='#ffcccc')
            dot.edge('input', 'exploit', style='dashed')
    
    def _add_xss_flow(
        self,
        dot: 'graphviz.Digraph',
        vulnerability: Dict[str, Any]
    ):
        """Add XSS attack flow nodes."""
        
        dot.node('attacker', 'Attacker', fillcolor='#ff6b6b')
        dot.node('inject', 'Inject Script\n<script>...', fillcolor='#ffd93d')
        dot.node('app', f"Application\n{vulnerability.get('file', 'Unknown')}", fillcolor='#6bcf7f')
        dot.node('render', 'Render\nUnescaped', fillcolor='#ff6b6b')
        dot.node('victim', 'Victim\nBrowser', fillcolor='#4ecdc4')
        dot.node('impact', 'Session Theft\n/Account Takeover', fillcolor='#ff0000', fontcolor='white')
        
        dot.edge('attacker', 'inject', 'crafts')
        dot.edge('inject', 'app', 'stores')
        dot.edge('app', 'render', 'no escaping')
        dot.edge('render', 'victim', 'sends to')
        dot.edge('victim', 'impact', 'executes')
    
    def _add_command_injection_flow(
        self,
        dot: 'graphviz.Digraph',
        vulnerability: Dict[str, Any]
    ):
        """Add command injection attack flow nodes."""
        
        dot.node('attacker', 'Attacker', fillcolor='#ff6b6b')
        dot.node('input', 'Malicious Input\n; rm -rf *', fillcolor='#ffd93d')
        dot.node('app', f"Application\n{vulnerability.get('file', 'Unknown')}", fillcolor='#6bcf7f')
        dot.node('shell', 'System\nShell', fillcolor='#ff6b6b')
        dot.node('os', 'Operating\nSystem', fillcolor='#4ecdc4')
        dot.node('impact', 'System\nCompromise', fillcolor='#ff0000', fontcolor='white')
        
        dot.edge('attacker', 'input', 'crafts')
        dot.edge('input', 'app', 'submits')
        dot.edge('app', 'shell', 'no sanitization')
        dot.edge('shell', 'os', 'executes')
        dot.edge('os', 'impact', 'results in')
    
    def _add_generic_flow(
        self,
        dot: 'graphviz.Digraph',
        vulnerability: Dict[str, Any]
    ):
        """Add generic vulnerability flow."""
        
        dot.node('attacker', 'Attacker', fillcolor='#ff6b6b')
        dot.node('vuln', f"{vulnerability.get('type', 'Vulnerability')}\nin {vulnerability.get('file', 'Unknown')}", fillcolor='#ffd93d')
        dot.node('impact', vulnerability.get('description', 'Security Impact')[:50], fillcolor='#ff0000', fontcolor='white')
        
        dot.edge('attacker', 'vuln', 'exploits')
        dot.edge('vuln', 'impact', 'leads to')
    
    def generate_severity_chart(
        self,
        vulnerabilities: List[Dict[str, Any]],
        filename: str = 'severity_distribution'
    ) -> Optional[str]:
        """Generate severity distribution chart."""
        
        if not GRAPHVIZ_AVAILABLE:
            return None
        
        try:
            # Count by severity
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'medium')
                counts[severity] = counts.get(severity, 0) + 1
            
            # Create bar chart representation
            dot = graphviz.Digraph(comment='Severity Distribution')
            dot.attr(rankdir='TB')
            
            # Create nodes for each severity with size based on count
            colors = {
                'critical': '#ff0000',
                'high': '#ff6600',
                'medium': '#ffcc00',
                'low': '#00ccff'
            }
            
            for severity, count in counts.items():
                if count > 0:
                    dot.node(
                        severity,
                        f'{severity.upper()}\n{count} found',
                        fillcolor=colors[severity],
                        style='filled',
                        fontcolor='white' if severity in ['critical', 'high'] else 'black',
                        fontsize=str(20 + count * 5)
                    )
            
            output_path = self.output_dir / filename
            dot.render(str(output_path), format='png', cleanup=True)
            
            logger.info(f"Generated severity chart: {output_path}.png")
            return f"{output_path}.png"
            
        except Exception as e:
            logger.error(f"Failed to generate severity chart: {e}")
            return None
    
    def generate_attack_chain_diagram(
        self,
        chain: Dict[str, Any],
        filename: str = None
    ) -> Optional[str]:
        """Generate diagram for multi-step attack chain."""
        
        if not GRAPHVIZ_AVAILABLE:
            return None
        
        try:
            chain_id = chain.get('id', 'CHAIN-000')
            
            dot = graphviz.Digraph(comment=f'Attack Chain: {chain_id}')
            dot.attr(rankdir='LR')
            dot.attr('node', shape='box', style='rounded,filled')
            
            # Add chain title
            dot.node('title', f"Attack Chain:\n{chain['name']}", fillcolor='#ffcccc', shape='ellipse')
            
            # Add steps
            prev_node = 'title'
            for i, vuln in enumerate(chain.get('vulnerabilities', []), 1):
                node_id = f"step{i}"
                label = f"Step {i}\n{vuln['type']}\n{vuln['file']}"
                color = '#ff6b6b' if i == 1 else '#ffd93d' if i == len(chain['vulnerabilities']) else '#ffeb99'
                
                dot.node(node_id, label, fillcolor=color)
                dot.edge(prev_node, node_id, f'enables')
                prev_node = node_id
            
            # Add final impact
            dot.node('impact', f"Impact:\n{chain.get('description', 'System Compromise')}", fillcolor='#ff0000', fontcolor='white')
            dot.edge(prev_node, 'impact', 'results in')
            
            if filename is None:
                filename = f"chain_{chain_id}"
            
            output_path = self.output_dir / filename
            dot.render(str(output_path), format='png', cleanup=True)
            
            logger.info(f"Generated attack chain diagram: {output_path}.png")
            return f"{output_path}.png"
            
        except Exception as e:
            logger.error(f"Failed to generate chain diagram: {e}")
            return None
    
    def generate_all_diagrams(
        self,
        vulnerabilities: List[Dict[str, Any]],
        chains: List[Dict[str, Any]] = None
    ) -> Dict[str, List[str]]:
        """
        Generate all available diagrams.
        
        Returns:
            Dictionary mapping diagram type to list of generated file paths
        """
        
        results = {
            'attack_flows': [],
            'chains': [],
            'charts': []
        }
        
        # Generate attack flows for top vulnerabilities
        for vuln in vulnerabilities[:5]:  # Top 5
            path = self.generate_attack_flow(vuln)
            if path:
                results['attack_flows'].append(path)
        
        # Generate chain diagrams
        if chains:
            for chain in chains:
                path = self.generate_attack_chain_diagram(chain)
                if path:
                    results['chains'].append(path)
        
        # Generate severity chart
        chart_path = self.generate_severity_chart(vulnerabilities)
        if chart_path:
            results['charts'].append(chart_path)
        
        return results
