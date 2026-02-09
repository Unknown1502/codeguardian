"""
Adversarial Battle - Red Team vs Blue Team Competition
Orchestrates iterative security testing with two competing Gemini 3 agents
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

from src.core.gemini_client import GeminiClient
from src.agents.red_team import RedTeamAgent
from src.agents.blue_team import BlueTeamAgent
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class AdversarialBattle:
    """
    Orchestrate Red Team vs Blue Team security competition.
    
    This creates a unique adversarial loop where:
    1. Red Team finds vulnerabilities and creates exploits
    2. Blue Team patches vulnerabilities and adds defenses
    3. Red Team tries to bypass defenses
    4. Process continues for N rounds or until no vulnerabilities found
    
    This demonstrates advanced multi-agent orchestration using Gemini 3.
    """
    
    def __init__(
        self,
        gemini_client: GeminiClient,
        max_rounds: int = 5,
        convergence_threshold: int = 2
    ):
        """
        Initialize adversarial battle.
        
        Args:
            gemini_client: Gemini 3 client for both agents
            max_rounds: Maximum number of red/blue iterations
            convergence_threshold: Stop if no new vulns found for N rounds
        """
        self.red_team = RedTeamAgent(gemini_client)
        self.blue_team = BlueTeamAgent(gemini_client)
        self.max_rounds = max_rounds
        self.convergence_threshold = convergence_threshold
        
        self.battle_history = []
        self.current_code = None
        self.original_code = None
        
    async def start_battle(
        self,
        code: str,
        language: str = 'python',
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Start adversarial battle between Red and Blue teams.
        
        Args:
            code: Code to test
            language: Programming language
            description: Optional description of the code
            
        Returns:
            Complete battle report with transcript and results
        """
        logger.info("[BATTLE] Starting Red Team vs Blue Team Battle!")
        logger.info(f"   Max Rounds: {self.max_rounds}")
        logger.info(f"   Convergence Threshold: {self.convergence_threshold}")
        
        self.original_code = code
        self.current_code = code
        self.battle_history = []
        
        start_time = datetime.now()
        rounds_without_vulns = 0
        
        for round_num in range(1, self.max_rounds + 1):
            logger.info(f"\n{'='*60}")
            logger.info(f"[ROUND] {round_num}/{self.max_rounds}")
            logger.info(f"{'='*60}\n")
            
            round_result = await self._execute_round(
                round_num=round_num,
                code=self.current_code,
                language=language
            )
            
            self.battle_history.append(round_result)
            
            # Check for convergence
            vulnerabilities_found = len(round_result.get('red_team_findings', {}).get('vulnerabilities', []))
            
            if vulnerabilities_found == 0:
                rounds_without_vulns += 1
                logger.info(f"[OK] No vulnerabilities found this round ({rounds_without_vulns}/{self.convergence_threshold})")
                
                if rounds_without_vulns >= self.convergence_threshold:
                    logger.info("[CONVERGED] Convergence reached! Code appears secure.")
                    break
            else:
                rounds_without_vulns = 0
                # Update current code with Blue Team's patches
                if round_result.get('blue_team_response', {}).get('patched_code'):
                    self.current_code = round_result['blue_team_response']['patched_code']
            
            # Small delay between rounds
            await asyncio.sleep(1)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Generate final report
        final_report = self._generate_battle_report(
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            rounds_completed=len(self.battle_history),
            language=language,
            description=description
        )
        
        logger.info(f"\n{'='*60}")
        logger.info("[COMPLETE] Battle Complete!")
        logger.info(f"   Duration: {duration:.1f}s")
        logger.info(f"   Rounds: {len(self.battle_history)}")
        logger.info(f"   Final Score - Red: {final_report['red_team_score']}, Blue: {final_report['blue_team_score']}")
        logger.info(f"{'='*60}\n")
        
        return final_report
    
    async def _execute_round(
        self,
        round_num: int,
        code: str,
        language: str
    ) -> Dict[str, Any]:
        """Execute a single round of Red vs Blue."""
        
        round_start = datetime.now()
        
        # Get previous round's defenses if available
        previous_defenses = None
        if len(self.battle_history) > 0:
            previous_round = self.battle_history[-1]
            previous_defenses = previous_round.get('blue_team_response', {}).get('patches', [])
        
        # 🔴 RED TEAM ATTACK
        logger.info("[RED TEAM] Analyzing for vulnerabilities...")
        red_team_findings = await self.red_team.analyze_target(
            code=code,
            language=language,
            previous_defenses=previous_defenses
        )
        
        vulnerabilities = red_team_findings.get('vulnerabilities', [])
        logger.info(f"[RED TEAM] Found {len(vulnerabilities)} vulnerabilities")
        
        for i, vuln in enumerate(vulnerabilities[:3], 1):  # Show top 3
            logger.info(f"   {i}. {vuln.get('type')} (Severity: {vuln.get('severity')})")
        
        # If no vulnerabilities, Blue Team wins this round
        if not vulnerabilities:
            logger.info("[BLUE TEAM] No vulnerabilities to patch. Defense holds!")
            return {
                'round': round_num,
                'timestamp': datetime.now().isoformat(),
                'duration': (datetime.now() - round_start).total_seconds(),
                'red_team_findings': red_team_findings,
                'blue_team_response': {'message': 'No vulnerabilities found - defense successful'},
                'winner': 'blue_team',
                'patched_code': code
            }
        
        # 🔵 BLUE TEAM DEFENSE
        logger.info("[BLUE TEAM] Implementing defenses...")
        
        previous_patches = None
        if len(self.battle_history) > 0:
            previous_patches = [
                p.get('defense_mechanism', 'unknown')
                for p in self.battle_history[-1].get('blue_team_response', {}).get('patches', [])
            ]
        
        blue_team_response = await self.blue_team.defend_against_attacks(
            code=code,
            red_team_findings=red_team_findings,
            language=language,
            previous_patches=previous_patches
        )
        
        patches_applied = len(blue_team_response.get('patches', []))
        logger.info(f"[BLUE TEAM] Applied {patches_applied} patches")
        
        for i, patch in enumerate(blue_team_response.get('patches', [])[:3], 1):  # Show top 3
            logger.info(f"   {i}. {patch.get('defense_mechanism')} for {patch.get('vulnerability_type')}")
        
        round_duration = (datetime.now() - round_start).total_seconds()
        
        return {
            'round': round_num,
            'timestamp': datetime.now().isoformat(),
            'duration': round_duration,
            'red_team_findings': red_team_findings,
            'blue_team_response': blue_team_response,
            'winner': 'red_team' if vulnerabilities else 'blue_team',
            'vulnerabilities_found': len(vulnerabilities),
            'patches_applied': patches_applied,
            'patched_code': blue_team_response.get('patched_code', code)
        }
    
    def _generate_battle_report(
        self,
        start_time: datetime,
        end_time: datetime,
        duration: float,
        rounds_completed: int,
        language: str,
        description: Optional[str]
    ) -> Dict[str, Any]:
        """Generate comprehensive battle report."""
        
        # Calculate statistics
        total_vulnerabilities = sum(
            len(r.get('red_team_findings', {}).get('vulnerabilities', []))
            for r in self.battle_history
        )
        
        total_patches = sum(
            len(r.get('blue_team_response', {}).get('patches', []))
            for r in self.battle_history
        )
        
        red_team_wins = sum(1 for r in self.battle_history if r.get('winner') == 'red_team')
        blue_team_wins = sum(1 for r in self.battle_history if r.get('winner') == 'blue_team')
        
        # Determine overall winner
        if blue_team_wins > red_team_wins:
            overall_winner = 'blue_team'
            winner_message = "🔵 Blue Team successfully defended the code!"
        elif red_team_wins > blue_team_wins:
            overall_winner = 'red_team'
            winner_message = "🔴 Red Team found persistent vulnerabilities!"
        else:
            overall_winner = 'draw'
            winner_message = "⚖️  Battle ended in a draw!"
        
        # Build transcript
        transcript = self._build_conversation_transcript()
        
        # Severity distribution
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for round_data in self.battle_history:
            for vuln in round_data.get('red_team_findings', {}).get('vulnerabilities', []):
                severity = vuln.get('severity', 'Medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'battle_id': f"battle_{int(start_time.timestamp())}",
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'language': language,
            'description': description,
            'rounds_completed': rounds_completed,
            'max_rounds': self.max_rounds,
            
            # Statistics
            'statistics': {
                'total_vulnerabilities': total_vulnerabilities,
                'total_patches': total_patches,
                'red_team_wins': red_team_wins,
                'blue_team_wins': blue_team_wins,
                'severity_distribution': severity_counts
            },
            
            # Scores
            'red_team_score': red_team_wins * 10 + total_vulnerabilities,
            'blue_team_score': blue_team_wins * 10 + total_patches,
            
            # Results
            'overall_winner': overall_winner,
            'winner_message': winner_message,
            'final_code': self.current_code,
            'original_code': self.original_code,
            
            # Detailed data
            'battle_history': self.battle_history,
            'conversation_transcript': transcript,
            
            # Agent statistics
            'red_team_stats': self.red_team.get_statistics(),
            'blue_team_stats': self.blue_team.get_statistics()
        }
    
    def _build_conversation_transcript(self) -> List[Dict[str, Any]]:
        """Build human-readable conversation transcript."""
        transcript = []
        
        for round_data in self.battle_history:
            round_num = round_data['round']
            
            # Red Team's turn
            red_findings = round_data.get('red_team_findings', {})
            vulnerabilities = red_findings.get('vulnerabilities', [])
            
            transcript.append({
                'speaker': 'Red Team',
                'round': round_num,
                'timestamp': round_data['timestamp'],
                'message': f"Found {len(vulnerabilities)} vulnerabilities",
                'details': {
                    'vulnerabilities': [
                        {
                            'type': v.get('type'),
                            'severity': v.get('severity'),
                            'line': v.get('line'),
                            'confidence': v.get('confidence')
                        }
                        for v in vulnerabilities
                    ],
                    'attack_chains': red_findings.get('attack_chains', [])
                }
            })
            
            # Blue Team's response
            blue_response = round_data.get('blue_team_response', {})
            patches = blue_response.get('patches', [])
            
            if patches:
                transcript.append({
                    'speaker': 'Blue Team',
                    'round': round_num,
                    'timestamp': round_data['timestamp'],
                    'message': f"Applied {len(patches)} patches to defend",
                    'details': {
                        'patches': [
                            {
                                'vulnerability_type': p.get('vulnerability_type'),
                                'defense_mechanism': p.get('defense_mechanism'),
                                'confidence': p.get('confidence')
                            }
                            for p in patches
                        ],
                        'strategy': blue_response.get('defense_strategy')
                    }
                })
            else:
                transcript.append({
                    'speaker': 'Blue Team',
                    'round': round_num,
                    'timestamp': round_data['timestamp'],
                    'message': blue_response.get('message', 'Defense successful'),
                    'details': {}
                })
        
        return transcript
    
    def export_report(self, filepath: str, format: str = 'json') -> None:
        """
        Export battle report to file.
        
        Args:
            filepath: Output file path
            format: Export format ('json' or 'html')
        """
        if not self.battle_history:
            logger.warning("No battle history to export")
            return
        
        report = self._generate_battle_report(
            start_time=datetime.fromisoformat(self.battle_history[0]['timestamp']),
            end_time=datetime.fromisoformat(self.battle_history[-1]['timestamp']),
            duration=sum(r['duration'] for r in self.battle_history),
            rounds_completed=len(self.battle_history),
            language='unknown',
            description=None
        )
        
        if format == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"Battle report exported to {filepath}")
        
        elif format == 'html':
            # TODO: Implement HTML export with visualization
            logger.warning("HTML export not yet implemented")
