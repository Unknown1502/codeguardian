"""
Attack Chain Analyzer

Traces data flows and vulnerability chains across codebase to show how
multiple vulnerabilities can be chained together for maximum impact.

Uses Gemini 3's 1M token context window to analyze entire codebases.
"""

import ast
import os
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path

from src.core.gemini_client import GeminiClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DataFlowNode:
    """Represents a point in the data flow."""
    file_path: str
    line_number: int
    function_name: str
    variable_name: str
    node_type: str  # 'source', 'sink', 'intermediate', 'vulnerability'
    taint_level: str  # 'user_input', 'sanitized', 'dangerous', 'safe'


@dataclass
class AttackChainLink:
    """Represents a single link in an attack chain."""
    vulnerability_id: str
    vulnerability_type: str
    severity: str
    location: str
    description: str
    prerequisite_links: List[str] = field(default_factory=list)
    enables_links: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    impact: Optional[str] = None


@dataclass
class AttackChain:
    """Represents a complete attack chain from entry point to critical impact."""
    chain_id: str
    name: str
    description: str
    severity: str  # Critical, High, Medium, Low
    entry_point: DataFlowNode
    target: DataFlowNode
    links: List[AttackChainLink]
    data_flow_path: List[DataFlowNode]
    exploitation_steps: List[str]
    total_impact_score: int
    mitigations: List[str] = field(default_factory=list)


class AttackChainAnalyzer:
    """
    Analyzes codebases to identify attack chains where multiple vulnerabilities
    can be chained together for maximum impact.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Attack Chain Analyzer.
        
        Args:
            api_key: Gemini API key (optional)
        """
        self.client = GeminiClient(api_key=api_key)
        self.data_flow_graph: Dict[str, List[DataFlowNode]] = {}
        self.vulnerability_map: Dict[str, AttackChainLink] = {}
        self.discovered_chains: List[AttackChain] = []
        
    def analyze_codebase(
        self,
        code_path: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[AttackChain]:
        """
        Analyze entire codebase to discover attack chains.
        
        Args:
            code_path: Path to codebase root
            vulnerabilities: List of discovered vulnerabilities
            
        Returns:
            List of discovered attack chains
        """
        logger.info(f"Starting attack chain analysis for {code_path}")
        
        # Step 1: Build data flow graph
        logger.info("Building data flow graph...")
        self._build_data_flow_graph(code_path)
        
        # Step 2: Map vulnerabilities to graph nodes
        logger.info("Mapping vulnerabilities to data flow...")
        self._map_vulnerabilities(vulnerabilities)
        
        # Step 3: Trace attack chains using Gemini
        logger.info("Discovering attack chains...")
        chains = self._discover_attack_chains(code_path)
        
        # Step 4: Calculate impact scores
        logger.info("Calculating impact scores...")
        self._calculate_impact_scores(chains)
        
        self.discovered_chains = chains
        logger.info(f"Discovered {len(chains)} attack chains")
        
        return chains
    
    def trace_data_flow(
        self,
        source_file: str,
        source_line: int,
        variable_name: str,
        codebase_path: str
    ) -> List[DataFlowNode]:
        """
        Trace how data flows from a source through the codebase.
        
        Args:
            source_file: Starting file
            source_line: Starting line number
            variable_name: Variable to trace
            codebase_path: Root path of codebase
            
        Returns:
            List of data flow nodes showing path
        """
        logger.info(f"Tracing data flow for {variable_name} from {source_file}:{source_line}")
        
        # Read relevant source files
        file_contents = self._read_relevant_files(codebase_path, source_file)
        
        prompt = self._build_data_flow_prompt(
            source_file=source_file,
            source_line=source_line,
            variable_name=variable_name,
            file_contents=file_contents
        )
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.3,
                thinking_level=5  # Maximum reasoning for complex flow analysis
            )
            
            flow_nodes = self._parse_data_flow_response(response)
            return flow_nodes
            
        except Exception as e:
            logger.error(f"Error tracing data flow: {e}")
            return []
    
    def find_vulnerability_connections(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """
        Find which vulnerabilities can enable or chain with others.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Mapping of vulnerability IDs to connected vulnerability IDs
        """
        logger.info("Finding vulnerability connections...")
        
        connections = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', str(vulnerabilities.index(vuln)))
            
            # Use Gemini to analyze which other vulnerabilities this one could enable
            connected = self._analyze_vulnerability_connections(vuln, vulnerabilities)
            connections[vuln_id] = connected
        
        return connections
    
    def _build_data_flow_graph(self, code_path: str) -> None:
        """Build initial data flow graph from static analysis."""
        python_files = list(Path(code_path).rglob("*.py"))
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    source = f.read()
                
                tree = ast.parse(source)
                self._extract_data_flows_from_ast(tree, str(file_path))
                
            except Exception as e:
                logger.warning(f"Error parsing {file_path}: {e}")
                continue
    
    def _extract_data_flows_from_ast(self, tree: ast.AST, file_path: str) -> None:
        """Extract data flow nodes from AST."""
        for node in ast.walk(tree):
            # Identify user input sources
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'attr'):
                    func_name = node.func.attr
                    if func_name in ['input', 'get', 'post', 'read', 'recv']:
                        flow_node = DataFlowNode(
                            file_path=file_path,
                            line_number=node.lineno,
                            function_name=func_name,
                            variable_name=self._extract_variable_name(node),
                            node_type='source',
                            taint_level='user_input'
                        )
                        
                        if file_path not in self.data_flow_graph:
                            self.data_flow_graph[file_path] = []
                        self.data_flow_graph[file_path].append(flow_node)
            
            # Identify dangerous sinks
            elif isinstance(node, ast.Call):
                if hasattr(node.func, 'id'):
                    func_name = node.func.id
                    if func_name in ['exec', 'eval', 'system', 'popen']:
                        flow_node = DataFlowNode(
                            file_path=file_path,
                            line_number=node.lineno,
                            function_name=func_name,
                            variable_name=self._extract_variable_name(node),
                            node_type='sink',
                            taint_level='dangerous'
                        )
                        
                        if file_path not in self.data_flow_graph:
                            self.data_flow_graph[file_path] = []
                        self.data_flow_graph[file_path].append(flow_node)
    
    def _extract_variable_name(self, node: ast.AST) -> str:
        """Extract variable name from AST node."""
        if hasattr(node, 'id'):
            return node.id
        elif hasattr(node, 'attr'):
            return node.attr
        return 'unknown'
    
    def _map_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Map vulnerabilities to attack chain links."""
        for vuln in vulnerabilities:
            link = AttackChainLink(
                vulnerability_id=vuln.get('id', str(vulnerabilities.index(vuln))),
                vulnerability_type=vuln.get('type', 'Unknown'),
                severity=vuln.get('severity', 'Unknown'),
                location=vuln.get('location', 'Unknown'),
                description=vuln.get('description', ''),
                attack_vector=vuln.get('attack_vector'),
                impact=vuln.get('impact')
            )
            
            self.vulnerability_map[link.vulnerability_id] = link
    
    def _discover_attack_chains(self, codebase_path: str) -> List[AttackChain]:
        """Use Gemini to discover potential attack chains."""
        # Read codebase context
        codebase_summary = self._build_codebase_summary(codebase_path)
        
        prompt = self._build_chain_discovery_prompt(codebase_summary)
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.4,
                thinking_level=5
            )
            
            chains = self._parse_attack_chains_response(response)
            return chains
            
        except Exception as e:
            logger.error(f"Error discovering attack chains: {e}")
            return []
    
    def _build_codebase_summary(self, code_path: str) -> str:
        """Build summary of codebase for analysis."""
        summary_parts = []
        
        # Add vulnerability summary
        summary_parts.append("DISCOVERED VULNERABILITIES:")
        for vuln_id, link in self.vulnerability_map.items():
            summary_parts.append(
                f"- [{vuln_id}] {link.vulnerability_type} at {link.location} "
                f"(Severity: {link.severity})"
            )
        
        # Add data flow summary
        summary_parts.append("\nDATA FLOW ENTRY POINTS:")
        entry_points = []
        for file_path, nodes in self.data_flow_graph.items():
            for node in nodes:
                if node.node_type == 'source':
                    entry_points.append(
                        f"- {node.function_name} at {file_path}:{node.line_number}"
                    )
        summary_parts.extend(entry_points[:20])  # Limit to top 20
        
        # Add dangerous sinks
        summary_parts.append("\nDANGEROUS SINKS:")
        sinks = []
        for file_path, nodes in self.data_flow_graph.items():
            for node in nodes:
                if node.node_type == 'sink':
                    sinks.append(
                        f"- {node.function_name} at {file_path}:{node.line_number}"
                    )
        summary_parts.extend(sinks[:20])
        
        return "\n".join(summary_parts)
    
    def _build_chain_discovery_prompt(self, codebase_summary: str) -> str:
        """Build prompt for discovering attack chains."""
        return f"""You are a security expert analyzing attack chains in a codebase.

{codebase_summary}

Analyze this information to discover ATTACK CHAINS - sequences where multiple vulnerabilities 
can be exploited together for maximum impact.

For each attack chain you discover, provide:

1. CHAIN NAME: Descriptive name (e.g., "Auth Bypass to RCE Chain")

2. DESCRIPTION: What the complete attack accomplishes

3. SEVERITY: Overall chain severity (Critical/High/Medium/Low)

4. ENTRY POINT: How attacker gains initial access

5. ATTACK STEPS: Ordered list of vulnerability exploitations
   - Which vulnerability is exploited
   - What it enables
   - How it connects to next step

6. FINAL IMPACT: What attacker achieves at the end

7. DATA FLOW PATH: How data flows from entry to final target

Focus on realistic, high-impact chains. Prioritize chains that:
- Lead to Remote Code Execution
- Expose sensitive data
- Allow privilege escalation
- Combine multiple vulnerabilities

Return response as JSON array of chain objects with fields:
name, description, severity, entry_point, steps (array), final_impact, data_flow_path (array of locations)
"""
    
    def _build_data_flow_prompt(
        self,
        source_file: str,
        source_line: int,
        variable_name: str,
        file_contents: Dict[str, str]
    ) -> str:
        """Build prompt for data flow tracing."""
        files_context = "\n\n".join([
            f"FILE: {path}\n{content[:2000]}"  # Limit each file to 2000 chars
            for path, content in file_contents.items()
        ])
        
        return f"""You are analyzing data flow in a Python codebase.

TRACE TARGET:
- Variable: {variable_name}
- Source: {source_file}:{source_line}

CODE CONTEXT:
{files_context}

Trace how the variable {variable_name} flows through the codebase:

1. Where is it assigned/defined?
2. How is it transformed or processed?
3. Where is it passed to other functions?
4. What functions/modules does it reach?
5. Is it ever used in dangerous operations (exec, eval, SQL queries, etc.)?

For each step in the flow, provide:
- File path
- Line number
- Function name
- Transformation applied (if any)
- Taint level (user_input/sanitized/dangerous/safe)

Return as JSON array of flow nodes with fields:
file_path, line_number, function_name, variable_name, node_type, taint_level
"""
    
    def _read_relevant_files(
        self,
        codebase_path: str,
        source_file: str,
        max_files: int = 10
    ) -> Dict[str, str]:
        """Read relevant files for analysis."""
        files = {}
        
        # Always include source file
        try:
            with open(source_file, 'r', encoding='utf-8') as f:
                files[source_file] = f.read()
        except Exception as e:
            logger.warning(f"Could not read source file {source_file}: {e}")
        
        # Include files in same directory
        source_dir = os.path.dirname(source_file)
        try:
            for file_name in os.listdir(source_dir):
                if file_name.endswith('.py'):
                    file_path = os.path.join(source_dir, file_name)
                    if len(files) >= max_files:
                        break
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            files[file_path] = f.read()
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"Error reading directory {source_dir}: {e}")
        
        return files
    
    def _analyze_vulnerability_connections(
        self,
        vuln: Dict[str, Any],
        all_vulnerabilities: List[Dict[str, Any]]
    ) -> List[str]:
        """Analyze which vulnerabilities this one connects to."""
        vuln_summary = f"{vuln.get('type')} at {vuln.get('location')}"
        other_vulns = "\n".join([
            f"[{i}] {v.get('type')} at {v.get('location')}"
            for i, v in enumerate(all_vulnerabilities)
            if v != vuln
        ])
        
        prompt = f"""Analyze vulnerability connections.

PRIMARY VULNERABILITY:
{vuln_summary}
Description: {vuln.get('description', 'None')}

OTHER VULNERABILITIES:
{other_vulns}

Which of the other vulnerabilities could this primary vulnerability enable or chain with?
Consider:
- Does exploiting this give access to other vulnerable code?
- Does this provide credentials/auth needed for other exploits?
- Does this allow bypassing protections for other vulnerabilities?

Return ONLY the indices (numbers in brackets) of connected vulnerabilities as a JSON array of numbers.
Example: [0, 3, 5]
If no connections, return: []
"""
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.2,
                thinking_level=3
            )
            
            # Parse response
            response = response.strip()
            if response.startswith('[') and response.endswith(']'):
                import json
                indices = json.loads(response)
                return [all_vulnerabilities[i].get('id', str(i)) for i in indices if i < len(all_vulnerabilities)]
            
        except Exception as e:
            logger.warning(f"Error analyzing connections: {e}")
        
        return []
    
    def _parse_data_flow_response(self, response: str) -> List[DataFlowNode]:
        """Parse data flow tracing response."""
        import json
        
        try:
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response.strip())
            
            nodes = []
            for item in data:
                node = DataFlowNode(
                    file_path=item.get('file_path', 'unknown'),
                    line_number=item.get('line_number', 0),
                    function_name=item.get('function_name', 'unknown'),
                    variable_name=item.get('variable_name', 'unknown'),
                    node_type=item.get('node_type', 'intermediate'),
                    taint_level=item.get('taint_level', 'unknown')
                )
                nodes.append(node)
            
            return nodes
            
        except Exception as e:
            logger.error(f"Error parsing data flow response: {e}")
            return []
    
    def _parse_attack_chains_response(self, response: str) -> List[AttackChain]:
        """Parse attack chain discovery response."""
        import json
        
        try:
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response.strip())
            
            chains = []
            for idx, item in enumerate(data):
                # Create entry and target nodes
                entry = DataFlowNode(
                    file_path=item.get('entry_point', {}).get('file', 'unknown'),
                    line_number=item.get('entry_point', {}).get('line', 0),
                    function_name=item.get('entry_point', {}).get('function', 'unknown'),
                    variable_name='entry',
                    node_type='source',
                    taint_level='user_input'
                )
                
                target = DataFlowNode(
                    file_path='target',
                    line_number=0,
                    function_name='target',
                    variable_name='target',
                    node_type='sink',
                    taint_level='dangerous'
                )
                
                # Parse links
                links = []
                for step in item.get('steps', []):
                    link = AttackChainLink(
                        vulnerability_id=f"chain_{idx}_step_{len(links)}",
                        vulnerability_type=step.get('vulnerability_type', 'Unknown'),
                        severity=step.get('severity', 'Medium'),
                        location=step.get('location', 'Unknown'),
                        description=step.get('description', ''),
                        attack_vector=step.get('attack_vector')
                    )
                    links.append(link)
                
                chain = AttackChain(
                    chain_id=f"chain_{idx}",
                    name=item.get('name', f'Chain {idx}'),
                    description=item.get('description', ''),
                    severity=item.get('severity', 'Medium'),
                    entry_point=entry,
                    target=target,
                    links=links,
                    data_flow_path=[],
                    exploitation_steps=item.get('steps', []),
                    total_impact_score=0
                )
                
                chains.append(chain)
            
            return chains
            
        except Exception as e:
            logger.error(f"Error parsing attack chains: {e}")
            return []
    
    def _calculate_impact_scores(self, chains: List[AttackChain]) -> None:
        """Calculate impact scores for attack chains."""
        for chain in chains:
            score = 0
            
            # Base score from severity
            severity_scores = {'Critical': 40, 'High': 30, 'Medium': 20, 'Low': 10}
            score += severity_scores.get(chain.severity, 15)
            
            # Add points for chain length
            score += len(chain.links) * 5
            
            # Add points for specific impacts
            if 'rce' in chain.description.lower() or 'remote code' in chain.description.lower():
                score += 30
            if 'privilege' in chain.description.lower():
                score += 20
            if 'data' in chain.description.lower() or 'leak' in chain.description.lower():
                score += 15
            
            chain.total_impact_score = min(score, 100)
