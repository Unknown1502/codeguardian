"""
CodeGuardian - Autonomous AI Security Audit Agent
Powered by Gemini 3 Pro

Main entry point for the security audit agent.
"""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.core.gemini_client import GeminiClient
from src.core.marathon_agent import MarathonAgent
from src.analyzers.code_analyzer import CodebaseAnalyzer
from src.analyzers.chain_detector import VulnerabilityChainDetector
from src.analyzers.compliance_mapper import ComplianceMapper
from src.scanners.vulnerability_scanner import VulnerabilityScanner
from src.generators.fix_generator import FixGenerator
from src.reporting.report_engine import ReportEngine
from src.visualization.diagram_generator import VisualizationEngine
from src.utils.logger import setup_logger

# Load environment variables
load_dotenv()

console = Console()
logger = setup_logger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CodeGuardian - Autonomous AI Security Audit Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python main.py --scan /path/to/codebase
  
  # With auto-fix enabled
  python main.py --scan /path/to/codebase --auto-fix
  
  # Focus on specific vulnerabilities
  python main.py --scan /path/to/codebase --focus sql-injection,xss
  
  # With live dashboard
  python main.py --scan /path/to/codebase --live
        """
    )
    
    parser.add_argument(
        '--scan',
        required=True,
        type=str,
        help='Path to the codebase to scan'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    parser.add_argument(
        '--auto-fix',
        action='store_true',
        help='Enable automatic fix generation and testing'
    )
    
    parser.add_argument(
        '--focus',
        type=str,
        help='Comma-separated list of vulnerability types to focus on'
    )
    
    parser.add_argument(
        '--max-time',
        type=int,
        default=14400,
        help='Maximum scan time in seconds (default: 4 hours)'
    )
    
    parser.add_argument(
        '--live',
        action='store_true',
        help='Enable live dashboard updates via WebSocket'
    )
    
    parser.add_argument(
        '--language',
        type=str,
        default='auto',
        help='Primary language to analyze (auto, python, javascript, java)'
    )
    
    parser.add_argument(
        '--simulate-attacks',
        action='store_true',
        default=True,
        help='Enable actual attack simulation (default: enabled)'
    )
    
    parser.add_argument(
        '--no-simulate',
        action='store_true',
        help='Disable attack simulation'
    )
    
    parser.add_argument(
        '--compliance',
        type=str,
        help='Check compliance (comma-separated: PCI-DSS,SOC2,HIPAA,GDPR,OWASP-Top-10)'
    )
    
    parser.add_argument(
        '--diagrams',
        action='store_true',
        help='Generate visual attack flow diagrams'
    )
    
    return parser.parse_args()


def print_banner():
    """Print the CodeGuardian banner."""
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║            🛡️  CodeGuardian v1.0.0              ║
    ║                                                   ║
    ║     Autonomous AI Security Audit Agent            ║
    ║          Powered by Gemini 3 Pro                  ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))


def validate_environment():
    """Validate required environment variables and configuration."""
    api_key = os.getenv('GEMINI_API_KEY')
    
    if not api_key or api_key == 'your_api_key_here':
        console.print("\n[bold red]❌ Error:[/bold red] GEMINI_API_KEY not configured!")
        console.print("\nPlease follow these steps:")
        console.print("1. Get your API key from: https://aistudio.google.com/")
        console.print("2. Copy .env.example to .env")
        console.print("3. Add your API key to the .env file")
        console.print("\n")
        sys.exit(1)
    
    return api_key


async def run_security_scan(args):
    """
    Main security scan orchestration.
    
    This function coordinates the entire security audit process:
    1. Code Analysis - Parse and understand the codebase
    2. Vulnerability Detection - Find potential security issues
    3. Attack Simulation - Test if vulnerabilities are exploitable
    4. Fix Generation - Auto-generate and test patches
    5. Reporting - Generate comprehensive security report
    """
    
    scan_path = Path(args.scan)
    if not scan_path.exists():
        console.print(f"[bold red]❌ Error:[/bold red] Path not found: {scan_path}")
        sys.exit(1)
    
    # Initialize components
    console.print("\n[bold cyan]🔧 Initializing CodeGuardian...[/bold cyan]")
    
    api_key = validate_environment()
    gemini_client = GeminiClient(api_key)
    
    marathon_agent = MarathonAgent(
        gemini_client=gemini_client,
        max_time=args.max_time,
        enable_live_updates=args.live
    )
    
    code_analyzer = CodebaseAnalyzer(scan_path, args.language)
    vuln_scanner = VulnerabilityScanner(
        gemini_client, 
        enable_attack_simulation=(args.simulate_attacks and not args.no_simulate)
    )
    chain_detector = VulnerabilityChainDetector(gemini_client)
    compliance_mapper = ComplianceMapper()
    fix_generator = FixGenerator(gemini_client) if args.auto_fix else None
    report_engine = ReportEngine(args.output)
    viz_engine = VisualizationEngine(args.output + '/diagrams') if args.diagrams else None
    
    # Start scan
    start_time = datetime.now()
    console.print(f"\n[bold green]▶️  Starting security audit...[/bold green]")
    console.print(f"💥 Attack Simulation: {'Enabled' if (args.simulate_attacks and not args.no_simulate) else 'Disabled'}")
    console.print(f"📁 Target: {scan_path}")
    console.print(f"⏱️  Max Time: {args.max_time // 3600}h {(args.max_time % 3600) // 60}m")
    console.print(f"🔧 Auto-Fix: {'Enabled' if args.auto_fix else 'Disabled'}")
    console.print(f"🎯 Focus: {args.focus if args.focus else 'All vulnerability types'}\n")
    
    try:
        # Phase 1: Code Analysis
        console.print("[bold yellow]Phase 1: Code Analysis[/bold yellow]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing codebase...", total=None)
            
            analysis_result = await code_analyzer.analyze()
            
            progress.update(task, completed=True)
        
        console.print(f"  ✓ Parsed {analysis_result['files_count']} files")
        console.print(f"  ✓ Context size: {analysis_result['total_tokens']:,} tokens")
        console.print(f"  ✓ Security-critical paths: {len(analysis_result['critical_paths'])}\n")
        
        # Phase 2: Vulnerability Detection
        console.print("[bold yellow]Phase 2: Vulnerability Detection[/bold yellow]")
        focus_types = args.focus.split(',') if args.focus else None
        
        vulnerabilities = await vuln_scanner.scan(
            analysis_result,
            marathon_agent,
            focus_types=focus_types
        )
        
        console.print(f"  ⚠️  Found {len(vulnerabilities)} potential vulnerabilities")
        console.print(f"  ⚡ Critical: {sum(1 for v in vulnerabilities if v['severity'] == 'critical')}")
        console.print(f"  🔴 High: {sum(1 for v in vulnerabilities if v['severity'] == 'high')}")
        console.print(f"  🟡 Medium: {sum(1 for v in vulnerabilities if v['severity'] == 'medium')}")
        
        # Show attack simulation results
        exploitable = sum(1 for v in vulnerabilities if v.get('attack_simulation', {}).get('exploitable'))
        if exploitable > 0:
            console.print(f"  💥 [bold red]CONFIRMED EXPLOITABLE: {exploitable}[/bold red]")
        console.print()
        
        # Phase 2.5: Attack Chain Detection
        console.print("[bold yellow]Phase 2.5: Attack Chain Analysis[/bold yellow]")
        chains = await chain_detector.detect_chains(vulnerabilities, analysis_result)
        
        if chains:
            console.print(f"  🔗 Found {len(chains)} multi-step attack chains")
            critical_chains = [c for c in chains if c.get('severity') == 'critical']
            if critical_chains:
                console.print(f"  ⚠️  [bold red]CRITICAL CHAINS: {len(critical_chains)}[/bold red]")
        console.print()
        
        # Phase 2.6: Compliance Mapping (if requested)
        compliance_results = None
        if args.compliance:
            console.print("[bold yellow]Phase 2.6: Compliance Mapping[/bold yellow]")
            frameworks = [f.strip() for f in args.compliance.split(',')]
            compliance_results = compliance_mapper.map_vulnerabilities(
                vulnerabilities,
                frameworks
            )
            console.print(f"  📋 Compliance violations: {compliance_results['total_violations']}")
            console.print(f"  🚨 Critical violations: {len(compliance_results['critical_violations'])}")
        console.print()
        
        # Phase 3: Fix Generation (if enabled)
        fixes = []
        if args.auto_fix and vulnerabilities:
            console.print("[bold yellow]Phase 3: Fix Generation & Testing[/bold yellow]")
            
            fixes = await fix_generator.generate_and_test_fixes(
                vulnerabilities,
                analysis_result,
                marathon_agent
            )
            
            console.print(f"  ✓ Generated {len(fixes)} patches")
            console.print(f"  ✓ Tests passing: {sum(1 for f in fixes if f['tests_pass'])}")
            console.print(f"  ✓ No regressions detected\n")
        
        # Phase 3.5: Diagram Generation (if enabled)
        diagrams = None
        if args.diagrams and viz_engine:
            console.print("[bold yellow]Phase 3.5: Generating Visual Diagrams[/bold yellow]")
            diagrams = viz_engine.generate_all_diagrams(vulnerabilities, chains)
            total_diagrams = sum(len(d) for d in diagrams.values())
            console.print(f"  📊 Generated {total_diagrams} diagrams")
        console.print()
        
        # Phase 4: Report Generation
        console.print("[bold yellow]Phase 4: Generating Report[/bold yellow]")
        
        report_path = await report_engine.generate_report(
            scan_path=scan_path,
            analysis=analysis_result,
            vulnerabilities=vulnerabilities,
            fixes=fixes,
            start_time=start_time,
            end_time=datetime.now(),
            chains=chains,
            compliance_results=compliance_results,
            diagrams=diagrams
        )
        
        # Summary
        duration = datetime.now() - start_time
        console.print("\n" + "━" * 60)
        console.print(f"[bold green]✨ Scan Complete![/bold green]")
        console.print(f"📊 Report: {report_path}")
        console.print(f"⏱️  Duration: {duration.seconds // 3600}h {(duration.seconds % 3600) // 60}m")
        console.print("━" * 60 + "\n")
        
        return 0
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Scan interrupted by user[/bold yellow]")
        return 1
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        console.print(f"\n[bold red]❌ Error:[/bold red] {str(e)}")
        return 1


def main():
    """Main entry point."""
    print_banner()
    
    args = parse_arguments()
    
    # Run async scan
    import asyncio
    exit_code = asyncio.run(run_security_scan(args))
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
