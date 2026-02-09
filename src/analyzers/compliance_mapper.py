"""
Compliance Mapper
Maps vulnerabilities to compliance requirements (SOC2, PCI-DSS, HIPAA, etc.)
Adds real business value beyond just finding bugs
"""

from typing import Dict, List, Any
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class ComplianceMapper:
    """
    Maps security vulnerabilities to compliance requirements.
    Shows real business impact beyond just technical issues.
    """
    
    # Compliance frameworks and their requirements
    COMPLIANCE_FRAMEWORKS = {
        'PCI-DSS': {
            'name': 'Payment Card Industry Data Security Standard',
            'requirements': {
                '6.5.1': {
                    'title': 'Injection flaws (SQL, command, etc.)',
                    'vuln_types': ['sql-injection', 'command-injection', 'xxe']
                },
                '6.5.7': {
                    'title': 'Cross-site scripting (XSS)',
                    'vuln_types': ['xss']
                },
                '6.5.8': {
                    'title': 'Improper access control',
                    'vuln_types': ['broken-access-control', 'broken-auth']
                },
                '6.5.3': {
                    'title': 'Insecure cryptographic storage',
                    'vuln_types': ['sensitive-data-exposure']
                },
                '6.5.10': {
                    'title': 'Broken authentication and session management',
                    'vuln_types': ['broken-auth']
                }
            }
        },
        'SOC2': {
            'name': 'Service Organization Control 2',
            'requirements': {
                'CC6.1': {
                    'title': 'Logical and physical access controls',
                    'vuln_types': ['broken-access-control', 'broken-auth']
                },
                'CC6.6': {
                    'title': 'Vulnerability management',
                    'vuln_types': ['sql-injection', 'xss', 'command-injection']
                },
                'CC6.7': {
                    'title': 'System monitoring',
                    'vuln_types': ['security-misconfiguration']
                },
                'CC6.8': {
                    'title': 'Change management',
                    'vuln_types': ['insecure-deserialization']
                }
            }
        },
        'HIPAA': {
            'name': 'Health Insurance Portability and Accountability Act',
            'requirements': {
                '164.308(a)(1)(ii)(D)': {
                    'title': 'Information system activity review',
                    'vuln_types': ['security-misconfiguration']
                },
                '164.308(a)(4)': {
                    'title': 'Access control',
                    'vuln_types': ['broken-access-control', 'broken-auth']
                },
                '164.312(a)(1)': {
                    'title': 'Access control',
                    'vuln_types': ['broken-auth']
                },
                '164.312(e)(1)': {
                    'title': 'Transmission security',
                    'vuln_types': ['sensitive-data-exposure']
                }
            }
        },
        'GDPR': {
            'name': 'General Data Protection Regulation',
            'requirements': {
                'Article 32': {
                    'title': 'Security of processing',
                    'vuln_types': ['sql-injection', 'xss', 'sensitive-data-exposure']
                },
                'Article 25': {
                    'title': 'Data protection by design',
                    'vuln_types': ['broken-access-control', 'security-misconfiguration']
                }
            }
        },
        'OWASP-Top-10': {
            'name': 'OWASP Top 10 2021',
            'requirements': {
                'A01': {
                    'title': 'Broken Access Control',
                    'vuln_types': ['broken-access-control']
                },
                'A02': {
                    'title': 'Cryptographic Failures',
                    'vuln_types': ['sensitive-data-exposure']
                },
                'A03': {
                    'title': 'Injection',
                    'vuln_types': ['sql-injection', 'command-injection', 'xxe']
                },
                'A07': {
                    'title': 'Identification and Authentication Failures',
                    'vuln_types': ['broken-auth']
                },
                'A08': {
                    'title': 'Software and Data Integrity Failures',
                    'vuln_types': ['insecure-deserialization']
                }
            }
        }
    }
    
    def __init__(self):
        """Initialize compliance mapper."""
        pass
    
    def map_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        frameworks: List[str] = None
    ) -> Dict[str, Any]:
        """
        Map vulnerabilities to compliance requirements.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            frameworks: Specific frameworks to check (default: all)
            
        Returns:
            Compliance mapping results
        """
        logger.info("Mapping vulnerabilities to compliance requirements...")
        
        if frameworks is None:
            frameworks = list(self.COMPLIANCE_FRAMEWORKS.keys())
        
        results = {
            'total_violations': 0,
            'by_framework': {},
            'critical_violations': [],
            'remediation_priority': []
        }
        
        for framework_id in frameworks:
            if framework_id not in self.COMPLIANCE_FRAMEWORKS:
                continue
            
            framework = self.COMPLIANCE_FRAMEWORKS[framework_id]
            violations = self._check_framework(framework_id, vulnerabilities)
            
            results['by_framework'][framework_id] = {
                'name': framework['name'],
                'violations': violations,
                'violation_count': len(violations),
                'compliance_score': self._calculate_score(framework, violations)
            }
            
            results['total_violations'] += len(violations)
            
            # Track critical violations
            for violation in violations:
                if violation['severity'] in ['critical', 'high']:
                    results['critical_violations'].append({
                        'framework': framework_id,
                        'requirement': violation['requirement_id'],
                        'vulnerability': violation['vulnerability_id']
                    })
        
        # Generate remediation priority
        results['remediation_priority'] = self._prioritize_remediation(
            vulnerabilities,
            results['by_framework']
        )
        
        logger.info(f"Found {results['total_violations']} compliance violations")
        
        return results
    
    def _check_framework(
        self,
        framework_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Check vulnerabilities against a specific framework."""
        
        framework = self.COMPLIANCE_FRAMEWORKS[framework_id]
        violations = []
        
        for req_id, requirement in framework['requirements'].items():
            # Find vulnerabilities that violate this requirement
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '').lower()
                
                if any(vt in vuln_type for vt in requirement['vuln_types']):
                    violations.append({
                        'requirement_id': req_id,
                        'requirement_title': requirement['title'],
                        'vulnerability_id': vuln['id'],
                        'vulnerability_type': vuln['type'],
                        'severity': vuln['severity'],
                        'file': vuln['file'],
                        'description': vuln.get('description', '')
                    })
        
        return violations
    
    def _calculate_score(
        self,
        framework: Dict[str, Any],
        violations: List[Dict[str, Any]]
    ) -> float:
        """Calculate compliance score (0-100)."""
        
        total_requirements = len(framework['requirements'])
        violated_requirements = len(set(v['requirement_id'] for v in violations))
        
        if total_requirements == 0:
            return 100.0
        
        return ((total_requirements - violated_requirements) / total_requirements) * 100
    
    def _prioritize_remediation(
        self,
        vulnerabilities: List[Dict[str, Any]],
        framework_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Prioritize vulnerabilities by compliance impact."""
        
        # Score each vulnerability by how many frameworks it violates
        vuln_scores = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln['id']
            score = 0
            frameworks_violated = []
            
            for framework_id, results in framework_results.items():
                for violation in results['violations']:
                    if violation['vulnerability_id'] == vuln_id:
                        score += 10  # Base score per framework
                        frameworks_violated.append(framework_id)
                        
                        # Bonus for critical frameworks
                        if framework_id in ['PCI-DSS', 'HIPAA']:
                            score += 20
            
            if score > 0:
                vuln_scores[vuln_id] = {
                    'vulnerability': vuln,
                    'compliance_score': score,
                    'frameworks_violated': list(set(frameworks_violated)),
                    'violation_count': len(frameworks_violated)
                }
        
        # Sort by compliance score
        sorted_vulns = sorted(
            vuln_scores.values(),
            key=lambda x: x['compliance_score'],
            reverse=True
        )
        
        return sorted_vulns[:10]  # Top 10 priorities
    
    def generate_compliance_report(
        self,
        compliance_results: Dict[str, Any]
    ) -> str:
        """Generate human-readable compliance report."""
        
        lines = []
        lines.append("=" * 70)
        lines.append("COMPLIANCE ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append("")
        
        lines.append(f"Total Compliance Violations: {compliance_results['total_violations']}")
        lines.append(f"Critical Violations: {len(compliance_results['critical_violations'])}")
        lines.append("")
        
        lines.append("-" * 70)
        lines.append("BY FRAMEWORK")
        lines.append("-" * 70)
        
        for framework_id, results in compliance_results['by_framework'].items():
            lines.append(f"\n📋 {results['name']} ({framework_id})")
            lines.append(f"   Compliance Score: {results['compliance_score']:.1f}%")
            lines.append(f"   Violations: {results['violation_count']}")
            
            if results['violations']:
                lines.append("\n   Requirements Violated:")
                seen_reqs = set()
                for violation in results['violations'][:5]:  # Top 5
                    req_id = violation['requirement_id']
                    if req_id not in seen_reqs:
                        lines.append(f"     • {req_id}: {violation['requirement_title']}")
                        seen_reqs.add(req_id)
        
        lines.append("\n" + "-" * 70)
        lines.append("REMEDIATION PRIORITY")
        lines.append("-" * 70)
        
        for i, item in enumerate(compliance_results['remediation_priority'][:5], 1):
            vuln = item['vulnerability']
            lines.append(f"\n{i}. {vuln['type']} in {vuln['file']}")
            lines.append(f"   Compliance Impact: {item['compliance_score']} points")
            lines.append(f"   Frameworks: {', '.join(item['frameworks_violated'])}")
        
        lines.append("\n" + "=" * 70)
        
        return "\n".join(lines)
    
    def export_audit_evidence(
        self,
        compliance_results: Dict[str, Any],
        output_format: str = 'json'
    ) -> Dict[str, Any]:
        """Export compliance evidence for auditors."""
        
        evidence = {
            'scan_date': None,  # Will be filled by caller
            'total_violations': compliance_results['total_violations'],
            'frameworks_assessed': list(compliance_results['by_framework'].keys()),
            'violations_by_framework': {},
            'remediation_plan': compliance_results['remediation_priority']
        }
        
        for framework_id, results in compliance_results['by_framework'].items():
            evidence['violations_by_framework'][framework_id] = {
                'name': results['name'],
                'score': results['compliance_score'],
                'violations': results['violations']
            }
        
        return evidence
