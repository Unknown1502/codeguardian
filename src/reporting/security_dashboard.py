"""
Security Score Dashboard
Tracks security metrics over time and generates beautiful visualizations
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class SecurityScoreboard:
    """
    Calculate and track security scores over time.
    
    Provides metrics like:
    - Overall security score (0-100)
    - Vulnerability trends
    - Fix adoption rate
    - Compliance coverage
    - Risk trajectory
    """
    
    def __init__(self, data_dir: str = ".codeguardian"):
        """
        Initialize scoreboard.
        
        Args:
            data_dir: Directory to store historical data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.history_file = self.data_dir / "score_history.json"
        self.history = self._load_history()
        
    def calculate_score(
        self,
        scan_results: Dict[str, Any],
        dependency_results: Optional[Dict[str, Any]] = None,
        compliance_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive security score.
        
        Args:
            scan_results: Vulnerability scan results
            dependency_results: Dependency scan results
            compliance_results: Compliance check results
            
        Returns:
            Score breakdown with overall score and component scores
        """
        logger.info("📊 Calculating security score...")
        
        # Component scores (0-100 each)
        scores = {}
        
        # 1. Code Vulnerability Score (40% weight)
        scores['code_vulnerabilities'] = self._score_code_vulnerabilities(scan_results)
        
        # 2. Dependency Security Score (30% weight)
        if dependency_results:
            scores['dependency_security'] = self._score_dependencies(dependency_results)
        else:
            scores['dependency_security'] = 100  # No data = assume OK
        
        # 3. Compliance Score (20% weight)
        if compliance_results:
            scores['compliance'] = self._score_compliance(compliance_results)
        else:
            scores['compliance'] = 50  # No data = neutral
        
        # 4. Fix Adoption Rate (10% weight)
        scores['fix_adoption'] = self._score_fix_adoption(scan_results)
        
        # Calculate weighted overall score
        overall_score = (
            scores['code_vulnerabilities'] * 0.40 +
            scores['dependency_security'] * 0.30 +
            scores['compliance'] * 0.20 +
            scores['fix_adoption'] * 0.10
        )
        
        # Determine grade
        grade = self._score_to_grade(overall_score)
        
        # Calculate trend
        trend = self._calculate_trend(overall_score)
        
        result = {
            'overall_score': round(overall_score, 1),
            'grade': grade,
            'trend': trend,
            'component_scores': scores,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'total_vulnerabilities': scan_results.get('summary', {}).get('total', 0),
                'critical_count': scan_results.get('summary', {}).get('critical', 0),
                'high_count': scan_results.get('summary', {}).get('high', 0),
                'medium_count': scan_results.get('summary', {}).get('medium', 0),
                'files_scanned': scan_results.get('summary', {}).get('files_scanned', 0)
            }
        }
        
        # Save to history
        self._save_score(result)
        
        logger.info(f"📊 Security Score: {overall_score:.1f}/100 ({grade}) {trend}")
        
        return result
    
    def _score_code_vulnerabilities(self, scan_results: Dict[str, Any]) -> float:
        """Score based on code vulnerabilities found."""
        summary = scan_results.get('summary', {})
        
        total = summary.get('total', 0)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        
        if total == 0:
            return 100.0
        
        # Calculate penalty points
        penalties = (
            critical * 20 +  # Each critical = -20 points
            high * 10 +       # Each high = -10 points
            medium * 5 +      # Each medium = -5 points
            low * 2           # Each low = -2 points
        )
        
        # Start at 100 and subtract penalties
        score = max(0, 100 - penalties)
        
        return score
    
    def _score_dependencies(self, dependency_results: Dict[str, Any]) -> float:
        """Score based on dependency vulnerabilities."""
        summary = dependency_results.get('summary', {})
        
        vulnerable = summary.get('vulnerable_dependencies', 0)
        exploitable = summary.get('actually_exploitable', 0)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        
        if vulnerable == 0:
            return 100.0
        
        # Heavy penalty for exploitable vulnerabilities
        penalties = (
            exploitable * 25 +  # Actually exploitable = -25 points
            critical * 15 +      # Critical CVE = -15 points
            high * 8             # High CVE = -8 points
        )
        
        score = max(0, 100 - penalties)
        
        return score
    
    def _score_compliance(self, compliance_results: Dict[str, Any]) -> float:
        """Score based on compliance coverage."""
        # Simplified - would integrate with actual compliance mapper
        total_controls = compliance_results.get('total_controls', 100)
        passing_controls = compliance_results.get('passing_controls', 50)
        
        if total_controls == 0:
            return 50.0
        
        compliance_rate = (passing_controls / total_controls) * 100
        
        return compliance_rate
    
    def _score_fix_adoption(self, scan_results: Dict[str, Any]) -> float:
        """Score based on how many fixes have been applied."""
        # Check if fixes were generated
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return 100.0
        
        fixes_available = sum(1 for v in vulnerabilities if v.get('fix'))
        fixes_applied = sum(1 for v in vulnerabilities if v.get('fix_applied', False))
        
        if fixes_available == 0:
            return 50.0  # No fixes available = neutral
        
        adoption_rate = (fixes_applied / fixes_available) * 100
        
        return adoption_rate
    
    def _score_to_grade(self, score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def _calculate_trend(self, current_score: float) -> str:
        """Calculate trend compared to previous scores."""
        if len(self.history) < 2:
            return '→'  # Not enough data
        
        previous_score = self.history[-1].get('overall_score', current_score)
        
        diff = current_score - previous_score
        
        if diff > 5:
            return '↑↑'  # Significantly improved
        elif diff > 1:
            return '↑'   # Improved
        elif diff < -5:
            return '↓↓'  # Significantly worse
        elif diff < -1:
            return '↓'   # Worse
        else:
            return '→'   # Stable
    
    def get_trends(self, days: int = 30) -> Dict[str, Any]:
        """
        Get security trends over time.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Trend data for visualization
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        relevant_scores = [
            score for score in self.history
            if datetime.fromisoformat(score['timestamp']) > cutoff_date
        ]
        
        if not relevant_scores:
            return {
                'data_points': 0,
                'message': 'No historical data available'
            }
        
        # Extract time series data
        timestamps = [s['timestamp'] for s in relevant_scores]
        overall_scores = [s['overall_score'] for s in relevant_scores]
        
        # Calculate statistics
        avg_score = sum(overall_scores) / len(overall_scores)
        min_score = min(overall_scores)
        max_score = max(overall_scores)
        
        # Calculate improvement rate
        if len(overall_scores) >= 2:
            first_score = overall_scores[0]
            last_score = overall_scores[-1]
            improvement = last_score - first_score
            improvement_rate = (improvement / days) if days > 0 else 0
        else:
            improvement = 0
            improvement_rate = 0
        
        # Vulnerability counts over time
        vuln_counts = [
            s['details'].get('total_vulnerabilities', 0)
            for s in relevant_scores
        ]
        
        return {
            'data_points': len(relevant_scores),
            'date_range': {
                'start': timestamps[0],
                'end': timestamps[-1]
            },
            'scores': {
                'timestamps': timestamps,
                'overall': overall_scores,
                'average': round(avg_score, 1),
                'min': min_score,
                'max': max_score
            },
            'improvement': {
                'total': round(improvement, 1),
                'rate_per_day': round(improvement_rate, 2),
                'direction': 'improving' if improvement > 0 else 'declining' if improvement < 0 else 'stable'
            },
            'vulnerabilities': {
                'timestamps': timestamps,
                'counts': vuln_counts,
                'average': sum(vuln_counts) / len(vuln_counts) if vuln_counts else 0
            }
        }
    
    def generate_dashboard_html(
        self,
        current_score: Dict[str, Any],
        trends: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate HTML dashboard with charts.
        
        Args:
            current_score: Current security score
            trends: Historical trend data
            
        Returns:
            HTML string
        """
        if trends is None:
            trends = self.get_trends(days=30)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CodeGuardian Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            color: white;
            margin-bottom: 40px;
        }}
        
        .header h1 {{
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header p {{
            font-size: 18px;
            opacity: 0.9;
        }}
        
        .score-hero {{
            background: white;
            border-radius: 20px;
            padding: 60px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }}
        
        .score-hero::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 8px;
            background: linear-gradient(90deg, #00ff87, #60efff);
        }}
        
        .score-display {{
            font-size: 120px;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
            margin-bottom: 20px;
        }}
        
        .grade {{
            display: inline-block;
            font-size: 72px;
            font-weight: 700;
            color: white;
            background: linear-gradient(135deg, #f093fb, #f5576c);
            padding: 20px 50px;
            border-radius: 50px;
            margin-bottom: 20px;
        }}
        
        .trend {{
            font-size: 48px;
            margin-left: 20px;
        }}
        
        .timestamp {{
            color: #666;
            font-size: 16px;
            margin-top: 20px;
        }}
        
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        
        .card h3 {{
            color: #333;
            font-size: 18px;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        
        .card-value {{
            font-size: 48px;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .card-label {{
            color: #666;
            font-size: 14px;
        }}
        
        .progress-bar {{
            height: 12px;
            background: #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
            margin-top: 10px;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00ff87, #60efff);
            transition: width 0.3s ease;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
        }}
        
        .chart-container h2 {{
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        
        canvas {{
            max-height: 400px;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-top: 20px;
        }}
        
        .severity-card {{
            text-align: center;
            padding: 20px;
            border-radius: 12px;
            color: white;
        }}
        
        .severity-critical {{ background: linear-gradient(135deg, #f5576c, #d63031); }}
        .severity-high {{ background: linear-gradient(135deg, #fd79a8, #e84393); }}
        .severity-medium {{ background: linear-gradient(135deg, #fdcb6e, #f39c12); }}
        .severity-low {{ background: linear-gradient(135deg, #74b9ff, #0984e3); }}
        
        .severity-count {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .severity-label {{
            font-size: 14px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CodeGuardian Security Dashboard</h1>
            <p>AI-Powered Security Analysis by Gemini 3</p>
        </div>
        
        <div class="score-hero">
            <div class="score-display">{current_score['overall_score']}<span style="font-size: 60px;">/100</span></div>
            <div>
                <span class="grade">{current_score['grade']}</span>
                <span class="trend">{current_score['trend']}</span>
            </div>
            <div class="timestamp">Last Updated: {datetime.fromisoformat(current_score['timestamp']).strftime('%B %d, %Y at %I:%M %p')}</div>
        </div>
        
        <div class="cards">
            <div class="card">
                <h3>📝 Code Vulnerabilities</h3>
                <div class="card-value">{current_score['component_scores']['code_vulnerabilities']:.0f}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {current_score['component_scores']['code_vulnerabilities']}%"></div>
                </div>
            </div>
            
            <div class="card">
                <h3>📦 Dependency Security</h3>
                <div class="card-value">{current_score['component_scores']['dependency_security']:.0f}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {current_score['component_scores']['dependency_security']}%"></div>
                </div>
            </div>
            
            <div class="card">
                <h3>✅ Compliance</h3>
                <div class="card-value">{current_score['component_scores']['compliance']:.0f}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {current_score['component_scores']['compliance']}%"></div>
                </div>
            </div>
            
            <div class="card">
                <h3>🔧 Fix Adoption</h3>
                <div class="card-value">{current_score['component_scores']['fix_adoption']:.0f}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {current_score['component_scores']['fix_adoption']}%"></div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🎯 Vulnerability Breakdown</h3>
            <div class="severity-grid">
                <div class="severity-card severity-critical">
                    <div class="severity-count">{current_score['details']['critical_count']}</div>
                    <div class="severity-label">Critical</div>
                </div>
                <div class="severity-card severity-high">
                    <div class="severity-count">{current_score['details']['high_count']}</div>
                    <div class="severity-label">High</div>
                </div>
                <div class="severity-card severity-medium">
                    <div class="severity-count">{current_score['details']['medium_count']}</div>
                    <div class="severity-label">Medium</div>
                </div>
                <div class="severity-card severity-low">
                    <div class="severity-count">0</div>
                    <div class="severity-label">Low</div>
                </div>
            </div>
        </div>
"""
        
        # Add trend charts if we have historical data
        if trends['data_points'] > 1:
            scores_data = trends['scores']['overall']
            timestamps = [datetime.fromisoformat(t).strftime('%m/%d') for t in trends['scores']['timestamps']]
            
            html += f"""
        <div class="chart-container">
            <h2>📈 Security Score Trend (Last 30 Days)</h2>
            <canvas id="scoreChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>🐛 Vulnerability Count Trend</h2>
            <canvas id="vulnChart"></canvas>
        </div>
        
        <script>
            // Score Trend Chart
            new Chart(document.getElementById('scoreChart'), {{
                type: 'line',
                data: {{
                    labels: {json.dumps(timestamps)},
                    datasets: [{{
                        label: 'Security Score',
                        data: {json.dumps(scores_data)},
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        borderWidth: 3,
                        fill: true,
                        tension: 0.4
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            max: 100,
                            ticks: {{
                                callback: function(value) {{
                                    return value + '/100';
                                }}
                            }}
                        }}
                    }}
                }}
            }});
            
            // Vulnerability Count Chart
            new Chart(document.getElementById('vulnChart'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(timestamps)},
                    datasets: [{{
                        label: 'Vulnerabilities',
                        data: {json.dumps(trends['vulnerabilities']['counts'])},
                        backgroundColor: 'rgba(245, 87, 108, 0.8)',
                        borderRadius: 8
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        </script>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html
    
    def _load_history(self) -> List[Dict[str, Any]]:
        """Load score history from disk."""
        if not self.history_file.exists():
            return []
        
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading history: {e}")
            return []
    
    def _save_score(self, score: Dict[str, Any]) -> None:
        """Save score to history."""
        self.history.append(score)
        
        # Keep only last 100 scores
        if len(self.history) > 100:
            self.history = self.history[-100:]
        
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving history: {e}")
