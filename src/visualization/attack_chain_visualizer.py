"""
Attack Chain Visualizer

Creates visual representations of security attack chains showing how
vulnerabilities connect and can be exploited in sequence.
"""

import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AttackChainVisualizer:
    """
    Generates visual representations of attack chains including Mermaid diagrams,
    interactive HTML visualizations, and text-based flow diagrams.
    """
    
    def __init__(self):
        """Initialize the visualizer."""
        self.output_dir = "reports/attack_chains"
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_mermaid_diagram(self, attack_chain: Any) -> str:
        """
        Generate Mermaid diagram syntax for an attack chain.
        
        Args:
            attack_chain: AttackChain object
            
        Returns:
            Mermaid diagram syntax as string
        """
        lines = ["```mermaid", "graph TD"]
        
        # Define styles
        lines.extend([
            "    classDef critical fill:#ff4444,stroke:#cc0000,stroke-width:3px,color:#fff",
            "    classDef high fill:#ff9944,stroke:#cc6600,stroke-width:2px",
            "    classDef medium fill:#ffdd44,stroke:#ccaa00,stroke-width:2px",
            "    classDef low fill:#44ff44,stroke:#00cc00,stroke-width:1px",
            "    classDef entry fill:#4444ff,stroke:#0000cc,stroke-width:2px,color:#fff",
            "    classDef target fill:#ff44ff,stroke:#cc00cc,stroke-width:3px,color:#fff",
            ""
        ])
        
        # Entry point
        entry_id = "entry"
        lines.append(f"    {entry_id}[\"Entry Point<br/>{attack_chain.entry_point.function_name}<br/>{attack_chain.entry_point.file_path}\"]")
        lines.append(f"    class {entry_id} entry")
        lines.append("")
        
        # Chain links
        prev_id = entry_id
        for idx, link in enumerate(attack_chain.links):
            node_id = f"vuln{idx}"
            
            # Sanitize text for Mermaid
            vuln_type = link.vulnerability_type.replace('"', "'")
            location = link.location.replace('"', "'")
            
            # Create node with vulnerability info
            lines.append(
                f"    {node_id}[\"{vuln_type}<br/>"
                f"Severity: {link.severity}<br/>"
                f"{location}\"]"
            )
            
            # Apply severity-based styling
            severity_class = link.severity.lower()
            lines.append(f"    class {node_id} {severity_class}")
            
            # Connect to previous node
            attack_desc = link.attack_vector or "Exploit"
            attack_desc = attack_desc.replace('"', "'")[:30]  # Limit length
            lines.append(f"    {prev_id} -->|{attack_desc}| {node_id}")
            lines.append("")
            
            prev_id = node_id
        
        # Target/Impact
        target_id = "target"
        impact = attack_chain.description[:50].replace('"', "'")
        lines.append(f"    {target_id}[\"Final Impact<br/>{impact}\"]")
        lines.append(f"    class {target_id} target")
        lines.append(f"    {prev_id} --> {target_id}")
        
        lines.append("```")
        
        return "\n".join(lines)
    
    def generate_html_visualization(
        self,
        attack_chains: List[Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate interactive HTML visualization of attack chains.
        
        Args:
            attack_chains: List of AttackChain objects
            output_path: Optional custom output path
            
        Returns:
            Path to generated HTML file
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"attack_chains_{timestamp}.html")
        
        html_content = self._build_html_template(attack_chains)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML visualization at {output_path}")
        return output_path
    
    def generate_text_diagram(self, attack_chain: Any) -> str:
        """
        Generate text-based ASCII diagram of attack chain.
        
        Args:
            attack_chain: AttackChain object
            
        Returns:
            ASCII diagram as string
        """
        lines = []
        lines.append("=" * 80)
        lines.append(f"ATTACK CHAIN: {attack_chain.name}")
        lines.append(f"Severity: {attack_chain.severity} | Impact Score: {attack_chain.total_impact_score}/100")
        lines.append("=" * 80)
        lines.append("")
        
        # Entry point
        lines.append("[ENTRY POINT]")
        lines.append(f"  Location: {attack_chain.entry_point.file_path}:{attack_chain.entry_point.line_number}")
        lines.append(f"  Function: {attack_chain.entry_point.function_name}")
        lines.append(f"  Type: User Input ({attack_chain.entry_point.taint_level})")
        lines.append("")
        lines.append("  |")
        lines.append("  v")
        lines.append("")
        
        # Chain steps
        for idx, link in enumerate(attack_chain.links, 1):
            lines.append(f"[STEP {idx}: {link.vulnerability_type}]")
            lines.append(f"  Severity: {link.severity}")
            lines.append(f"  Location: {link.location}")
            lines.append(f"  Description: {link.description}")
            if link.attack_vector:
                lines.append(f"  Attack Vector: {link.attack_vector}")
            lines.append("")
            
            if idx < len(attack_chain.links):
                lines.append("  |")
                lines.append("  | Enables")
                lines.append("  |")
                lines.append("  v")
                lines.append("")
        
        # Final impact
        lines.append("[FINAL IMPACT]")
        lines.append(f"  {attack_chain.description}")
        lines.append("")
        
        # Mitigations
        if attack_chain.mitigations:
            lines.append("[RECOMMENDED MITIGATIONS]")
            for mitigation in attack_chain.mitigations:
                lines.append(f"  - {mitigation}")
            lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def generate_summary_report(
        self,
        attack_chains: List[Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate summary report of all attack chains.
        
        Args:
            attack_chains: List of AttackChain objects
            output_path: Optional custom output path
            
        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"chain_summary_{timestamp}.txt")
        
        lines = []
        lines.append("=" * 80)
        lines.append("ATTACK CHAIN ANALYSIS SUMMARY")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        lines.append("")
        
        # Statistics
        lines.append("STATISTICS")
        lines.append("-" * 80)
        lines.append(f"Total Attack Chains Discovered: {len(attack_chains)}")
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for chain in attack_chains:
            severity_counts[chain.severity] = severity_counts.get(chain.severity, 0) + 1
        
        lines.append(f"  - Critical: {severity_counts['Critical']}")
        lines.append(f"  - High: {severity_counts['High']}")
        lines.append(f"  - Medium: {severity_counts['Medium']}")
        lines.append(f"  - Low: {severity_counts['Low']}")
        lines.append("")
        
        avg_length = sum(len(chain.links) for chain in attack_chains) / len(attack_chains) if attack_chains else 0
        lines.append(f"Average Chain Length: {avg_length:.1f} vulnerabilities")
        
        max_impact = max((chain.total_impact_score for chain in attack_chains), default=0)
        lines.append(f"Maximum Impact Score: {max_impact}/100")
        lines.append("")
        
        # Top chains
        lines.append("TOP ATTACK CHAINS (by impact)")
        lines.append("-" * 80)
        
        sorted_chains = sorted(attack_chains, key=lambda x: x.total_impact_score, reverse=True)
        for idx, chain in enumerate(sorted_chains[:10], 1):
            lines.append(f"{idx}. {chain.name}")
            lines.append(f"   Severity: {chain.severity} | Impact: {chain.total_impact_score}/100")
            lines.append(f"   Steps: {len(chain.links)} | Description: {chain.description[:80]}")
            lines.append("")
        
        # Detailed chains
        lines.append("=" * 80)
        lines.append("DETAILED ATTACK CHAINS")
        lines.append("=" * 80)
        lines.append("")
        
        for chain in sorted_chains:
            lines.append(self.generate_text_diagram(chain))
            lines.append("")
        
        # Write report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        
        logger.info(f"Generated summary report at {output_path}")
        return output_path
    
    def _build_html_template(self, attack_chains: List[Any]) -> str:
        """Build HTML template with interactive visualization."""
        
        # Convert chains to JSON for JavaScript
        chains_json = json.dumps([
            {
                'id': chain.chain_id,
                'name': chain.name,
                'description': chain.description,
                'severity': chain.severity,
                'impact_score': chain.total_impact_score,
                'links': [
                    {
                        'id': link.vulnerability_id,
                        'type': link.vulnerability_type,
                        'severity': link.severity,
                        'location': link.location,
                        'description': link.description
                    }
                    for link in chain.links
                ]
            }
            for chain in attack_chains
        ])
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Chain Visualization - CodeGuardian</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card .label {{
            color: #666;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        
        .chain-list {{
            padding: 30px;
        }}
        
        .chain-item {{
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .chain-item:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            transform: translateY(-2px);
        }}
        
        .chain-header {{
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .chain-header h3 {{
            font-size: 1.3em;
            margin-bottom: 5px;
        }}
        
        .chain-meta {{
            display: flex;
            gap: 20px;
            font-size: 0.9em;
            color: #666;
        }}
        
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{
            background: #d32f2f;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #f57c00;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #fbc02d;
            color: #333;
        }}
        
        .severity-badge.low {{
            background: #388e3c;
            color: white;
        }}
        
        .chain-content {{
            padding: 20px;
            display: none;
        }}
        
        .chain-content.active {{
            display: block;
        }}
        
        .chain-description {{
            margin-bottom: 20px;
            padding: 15px;
            background: #f0f7ff;
            border-left: 4px solid #2196f3;
            border-radius: 4px;
        }}
        
        .vulnerability-step {{
            margin-bottom: 15px;
            padding: 15px;
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            border-radius: 4px;
        }}
        
        .vulnerability-step h4 {{
            margin-bottom: 8px;
            color: #e65100;
        }}
        
        .vulnerability-step p {{
            margin: 5px 0;
            font-size: 0.95em;
        }}
        
        .mermaid-diagram {{
            margin-top: 20px;
            padding: 20px;
            background: #fafafa;
            border-radius: 8px;
            overflow-x: auto;
        }}
        
        .impact-score {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            border-top: 2px solid #e0e0e0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Attack Chain Analysis</h1>
            <p>Comprehensive visualization of security vulnerability chains</p>
        </header>
        
        <div class="stats" id="stats"></div>
        
        <div class="chain-list" id="chainList"></div>
        
        <footer>
            <p>Generated by CodeGuardian | Powered by Gemini 3</p>
            <p>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
    
    <script>
        const attackChains = {chains_json};
        
        // Calculate statistics
        function calculateStats() {{
            const stats = {{
                total: attackChains.length,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                avgImpact: 0,
                totalVulns: 0
            }};
            
            attackChains.forEach(chain => {{
                stats[chain.severity.toLowerCase()]++;
                stats.avgImpact += chain.impact_score;
                stats.totalVulns += chain.links.length;
            }});
            
            stats.avgImpact = stats.total > 0 ? (stats.avgImpact / stats.total).toFixed(1) : 0;
            
            return stats;
        }}
        
        // Render statistics
        function renderStats() {{
            const stats = calculateStats();
            const statsContainer = document.getElementById('stats');
            
            statsContainer.innerHTML = `
                <div class="stat-card">
                    <div class="number">${{stats.total}}</div>
                    <div class="label">Total Chains</div>
                </div>
                <div class="stat-card">
                    <div class="number critical">${{stats.critical}}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="number high">${{stats.high}}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card">
                    <div class="number medium">${{stats.medium}}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="number">${{stats.avgImpact}}</div>
                    <div class="label">Avg Impact Score</div>
                </div>
                <div class="stat-card">
                    <div class="number">${{stats.totalVulns}}</div>
                    <div class="label">Total Vulnerabilities</div>
                </div>
            `;
        }}
        
        // Render attack chains
        function renderChains() {{
            const listContainer = document.getElementById('chainList');
            
            const sortedChains = [...attackChains].sort((a, b) => b.impact_score - a.impact_score);
            
            sortedChains.forEach((chain, index) => {{
                const chainElement = document.createElement('div');
                chainElement.className = 'chain-item';
                chainElement.innerHTML = `
                    <div class="chain-header" onclick="toggleChain(${{index}})">
                        <div>
                            <h3>${{chain.name}}</h3>
                            <div class="chain-meta">
                                <span class="severity-badge ${{chain.severity.toLowerCase()}}">${{chain.severity}}</span>
                                <span class="impact-score">Impact: ${{chain.impact_score}}/100</span>
                                <span>${{chain.links.length}} vulnerabilities</span>
                            </div>
                        </div>
                        <span id="toggle-${{index}}">▼</span>
                    </div>
                    <div class="chain-content" id="content-${{index}}">
                        <div class="chain-description">
                            <strong>Description:</strong> ${{chain.description}}
                        </div>
                        <h4>Attack Steps:</h4>
                        ${{chain.links.map((link, idx) => `
                            <div class="vulnerability-step">
                                <h4>Step ${{idx + 1}}: ${{link.type}}</h4>
                                <p><strong>Severity:</strong> ${{link.severity}}</p>
                                <p><strong>Location:</strong> ${{link.location}}</p>
                                <p><strong>Description:</strong> ${{link.description}}</p>
                            </div>
                        `).join('')}}
                    </div>
                `;
                
                listContainer.appendChild(chainElement);
            }});
        }}
        
        // Toggle chain visibility
        function toggleChain(index) {{
            const content = document.getElementById(`content-${{index}}`);
            const toggle = document.getElementById(`toggle-${{index}}`);
            
            content.classList.toggle('active');
            toggle.textContent = content.classList.contains('active') ? '▲' : '▼';
        }}
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {{
            renderStats();
            renderChains();
            mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
        }});
    </script>
</body>
</html>
"""
    
    def export_json(
        self,
        attack_chains: List[Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Export attack chains as JSON for further processing.
        
        Args:
            attack_chains: List of AttackChain objects
            output_path: Optional custom output path
            
        Returns:
            Path to generated JSON file
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"attack_chains_{timestamp}.json")
        
        chains_data = []
        for chain in attack_chains:
            chain_dict = {
                'chain_id': chain.chain_id,
                'name': chain.name,
                'description': chain.description,
                'severity': chain.severity,
                'impact_score': chain.total_impact_score,
                'entry_point': {
                    'file': chain.entry_point.file_path,
                    'line': chain.entry_point.line_number,
                    'function': chain.entry_point.function_name
                },
                'links': [
                    {
                        'id': link.vulnerability_id,
                        'type': link.vulnerability_type,
                        'severity': link.severity,
                        'location': link.location,
                        'description': link.description,
                        'attack_vector': link.attack_vector
                    }
                    for link in chain.links
                ],
                'mitigations': chain.mitigations
            }
            chains_data.append(chain_dict)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(chains_data, f, indent=2)
        
        logger.info(f"Exported attack chains to {output_path}")
        return output_path
