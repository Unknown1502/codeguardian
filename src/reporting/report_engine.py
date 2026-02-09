"""
Report Engine
Generates comprehensive security reports with visualizations
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Template

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class ReportEngine:
    """
    Generate comprehensive security audit reports.
    Outputs: HTML, JSON, and optionally PDF
    """
    
    def __init__(self, output_dir: str = './reports'):
        """
        Initialize report engine.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_report(
        self,
        scan_path: Path,
        analysis: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        fixes: List[Dict[str, Any]],
        start_time: datetime,
        end_time: datetime,
        chains: List[Dict[str, Any]] = None,
        compliance_results: Dict[str, Any] = None,
        diagrams: Dict[str, List[str]] = None
    ) -> str:
        """
        Generate comprehensive security report.
        
        Args:
            scan_path: Path that was scanned
            analysis: Codebase analysis results
            vulnerabilities: Detected vulnerabilities
            fixes: Generated fixes
            start_time: Scan start time
            end_time: Scan end time
            
        Returns:
            Path to generated report
        """
        logger.info("Generating security report")
        
        # Calculate metrics
        duration = (end_time - start_time).total_seconds()
        
        report_data = {
            'metadata': {
                'scan_target': str(scan_path),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'duration_formatted': self._format_duration(duration),
                'generated_at': datetime.now().isoformat(),
                'codeguardian_version': '1.0.0'
            },
            'codebase': {
                'total_files': analysis['files_count'],
                'total_loc': analysis['total_loc'],
                'languages': analysis['supported_languages'],
                'dependencies_count': len(analysis['dependencies']),
                'critical_paths_count': len(analysis['critical_paths'])
            },
            'vulnerabilities': {
                'total': len(vulnerabilities),
                'by_severity': self._group_by_severity(vulnerabilities),
                'by_type': self._group_by_type(vulnerabilities),
                'list': vulnerabilities
            },
            'fixes': {
                'total': len(fixes),
                'passing': sum(1 for f in fixes if f.get('tests_pass', False)),
                'failed': sum(1 for f in fixes if not f.get('tests_pass', False)),
                'list': fixes
            },
            'chains': chains or [],
            'compliance': compliance_results,
            'diagrams': diagrams or {}
        }
        
        # Generate timestamp for filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate JSON report
        json_path = self.output_dir / f'report_{timestamp}.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report saved: {json_path}")
        
        # Generate HTML report
        html_path = self.output_dir / f'report_{timestamp}.html'
        html_content = self._generate_html_report(report_data)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved: {html_path}")
        
        # Generate executive summary
        summary_path = self.output_dir / f'summary_{timestamp}.txt'
        summary_content = self._generate_summary(report_data)
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary_content)
        
        logger.info(f"Summary saved: {summary_path}")
        
        return str(html_path)
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report from data."""
        
        template = Template('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeGuardian Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            background: #f5f5f5;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #2563eb; font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { color: #666; font-size: 1.1em; }
        .metadata { background: #f8fafc; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .metadata-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metadata-item { padding: 10px; }
        .metadata-item .label { font-weight: 600; color: #64748b; font-size: 0.9em; }
        .metadata-item .value { font-size: 1.2em; color: #1e293b; margin-top: 5px; }
        .section { margin-bottom: 40px; }
        .section-title { font-size: 1.8em; color: #1e293b; margin-bottom: 20px; border-left: 4px solid #2563eb; padding-left: 15px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card.critical { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        .stat-card.high { background: linear-gradient(135deg, #f97316 0%, #ea580c 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #eab308 0%, #ca8a04 100%); }
        .stat-card.low { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); }
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { font-size: 0.9em; opacity: 0.9; margin-top: 5px; }
        .vulnerability { background: #f8fafc; border-left: 4px solid #64748b; padding: 20px; margin-bottom: 20px; border-radius: 4px; }
        .vulnerability.critical { border-left-color: #ef4444; }
        .vulnerability.high { border-left-color: #f97316; }
        .vulnerability.medium { border-left-color: #eab308; }
        .vulnerability.low { border-left-color: #3b82f6; }
        .vulnerability-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; }
        .vulnerability-title { font-size: 1.2em; font-weight: 600; color: #1e293b; }
        .severity-badge { padding: 5px 15px; border-radius: 20px; font-size: 0.85em; font-weight: 600; text-transform: uppercase; }
        .severity-badge.critical { background: #fef2f2; color: #ef4444; }
        .severity-badge.high { background: #fff7ed; color: #f97316; }
        .severity-badge.medium { background: #fefce8; color: #eab308; }
        .severity-badge.low { background: #eff6ff; color: #3b82f6; }
        .vulnerability-details { margin-top: 15px; }
        .detail-row { margin-bottom: 10px; }
        .detail-label { font-weight: 600; color: #64748b; display: inline-block; width: 100px; }
        .detail-value { color: #1e293b; }
        code { background: #1e293b; color: #e2e8f0; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .code-block { background: #1e293b; color: #e2e8f0; padding: 15px; border-radius: 6px; overflow-x: auto; margin: 10px 0; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .fix { background: #f0fdf4; border-left: 4px solid #22c55e; padding: 20px; margin-bottom: 20px; border-radius: 4px; }
        .fix-header { font-weight: 600; color: #166534; margin-bottom: 10px; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; text-align: center; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CodeGuardian</h1>
            <div class="subtitle">Autonomous AI Security Audit Report</div>
        </div>
        
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="label">Scan Target</div>
                    <div class="value">{{ data.metadata.scan_target }}</div>
                </div>
                <div class="metadata-item">
                    <div class="label">Duration</div>
                    <div class="value">{{ data.metadata.duration_formatted }}</div>
                </div>
                <div class="metadata-item">
                    <div class="label">Files Analyzed</div>
                    <div class="value">{{ data.codebase.total_files }}</div>
                </div>
                <div class="metadata-item">
                    <div class="label">Lines of Code</div>
                    <div class="value">{{ "{:,}".format(data.codebase.total_loc) }}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="stats">
                <div class="stat-card critical">
                    <div class="number">{{ data.vulnerabilities.by_severity.get('critical', 0) }}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{{ data.vulnerabilities.by_severity.get('high', 0) }}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{{ data.vulnerabilities.by_severity.get('medium', 0) }}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{{ data.vulnerabilities.by_severity.get('low', 0) }}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Detected Vulnerabilities</h2>
            {% for vuln in data.vulnerabilities.list[:20] %}
            <div class="vulnerability {{ vuln.severity }}">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{{ vuln.title or vuln.type }}</div>
                    <span class="severity-badge {{ vuln.severity }}">{{ vuln.severity }}</span>
                </div>
                <div class="vulnerability-details">
                    <div class="detail-row">
                        <span class="detail-label">ID:</span>
                        <span class="detail-value"><code>{{ vuln.id }}</code></span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value"><code>{{ vuln.file }}</code></span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Type:</span>
                        <span class="detail-value">{{ vuln.type }} ({{ vuln.cwe }})</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <div class="detail-value">{{ vuln.description }}</div>
                    </div>
                    {% if vuln.fix_suggestion %}
                    <div class="detail-row">
                        <span class="detail-label">Recommendation:</span>
                        <div class="detail-value">{{ vuln.fix_suggestion }}</div>
                    </div>
                    {% endif %}
                    {% if vuln.attack_simulation and vuln.attack_simulation.exploitable %}
                    <div class="detail-row" style="margin-top: 15px; padding: 10px; background: #fee; border-left: 3px solid #ef4444;">
                        <strong style="color: #dc2626;">⚠️ CONFIRMED EXPLOITABLE</strong>
                        <div style="margin-top: 5px;">
                            <strong>Method:</strong> {{ vuln.attack_simulation.method }}<br>
                            <strong>Impact:</strong> {{ vuln.attack_simulation.impact }}<br>
                            <strong>Payload:</strong> <code>{{ vuln.attack_simulation.payload }}</code>
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        {% if data.fixes.list %}
        <div class="section">
            <h2 class="section-title">Auto-Generated Fixes</h2>
            <p>CodeGuardian generated {{ data.fixes.passing }} / {{ data.fixes.total }} passing fixes.</p>
            {% for fix in data.fixes.list if fix.tests_pass %}
            <div class="fix">
                <div class="fix-header">✓ Fix for {{ fix.vulnerability_type }} in {{ fix.file }}</div>
                <div>{{ fix.explanation }}</div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Generated by CodeGuardian v{{ data.metadata.codeguardian_version }}</p>
            <p>Powered by Gemini 3 Pro | {{ data.metadata.generated_at }}</p>
        </div>
    </div>
</body>
</html>
        ''')
        
        return template.render(data=data)
    
    def _generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate plain text executive summary."""
        
        lines = []
        lines.append("=" * 70)
        lines.append("CodeGuardian Security Audit - Executive Summary")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Scan Target:     {data['metadata']['scan_target']}")
        lines.append(f"Scan Duration:   {data['metadata']['duration_formatted']}")
        lines.append(f"Generated:       {data['metadata']['generated_at']}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("CODEBASE METRICS")
        lines.append("-" * 70)
        lines.append(f"Total Files:     {data['codebase']['total_files']}")
        lines.append(f"Lines of Code:   {data['codebase']['total_loc']:,}")
        lines.append(f"Languages:       {', '.join(data['codebase']['languages'])}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("SECURITY FINDINGS")
        lines.append("-" * 70)
        lines.append(f"Total Vulnerabilities: {data['vulnerabilities']['total']}")
        lines.append("")
        
        by_severity = data['vulnerabilities']['by_severity']
        lines.append(f"  🔴 Critical:  {by_severity.get('critical', 0)}")
        lines.append(f"  🟠 High:      {by_severity.get('high', 0)}")
        lines.append(f"  🟡 Medium:    {by_severity.get('medium', 0)}")
        lines.append(f"  🔵 Low:       {by_severity.get('low', 0)}")
        lines.append("")
        
        lines.append("-" * 70)
        lines.append("AUTO-FIXES")
        lines.append("-" * 70)
        lines.append(f"Generated:  {data['fixes']['total']}")
        lines.append(f"Passing:    {data['fixes']['passing']}")
        lines.append(f"Failed:     {data['fixes']['failed']}")
        lines.append("")
        
        lines.append("=" * 70)
        lines.append("End of Summary")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _group_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Group vulnerabilities by severity."""
        result = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            result[severity] = result.get(severity, 0) + 1
        return result
    
    def _group_by_type(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Group vulnerabilities by type."""
        result = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            result[vuln_type] = result.get(vuln_type, 0) + 1
        return result
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if secs > 0 or not parts:
            parts.append(f"{secs}s")
        
        return " ".join(parts)
