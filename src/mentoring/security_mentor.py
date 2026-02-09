"""
AI Security Mentor

Uses Gemini 3's extended reasoning and conversational capabilities to educate
developers about security vulnerabilities in their code.
"""

import json
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

from src.core.gemini_client import GeminiClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LearningModule:
    """Represents an educational module about a specific vulnerability."""
    vulnerability_type: str
    severity: str
    location: str
    explanation_simple: str
    explanation_technical: str
    attack_scenario: str
    real_world_example: str
    remediation_steps: List[str]
    quiz_questions: List[Dict[str, Any]]
    additional_resources: List[str]


@dataclass
class MentorSession:
    """Tracks an interactive mentoring session."""
    session_id: str
    vulnerability_focus: str
    user_level: str  # beginner, intermediate, advanced
    interactions: List[Dict[str, str]]
    quiz_score: Optional[int] = None


class SecurityMentor:
    """
    AI-powered security mentor that provides interactive education
    about vulnerabilities discovered in code.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Security Mentor.
        
        Args:
            api_key: Gemini API key (optional, will use environment variable if not provided)
        """
        self.client = GeminiClient(api_key=api_key)
        self.sessions: Dict[str, MentorSession] = {}
        
    def create_learning_module(
        self,
        vulnerability: Dict[str, Any],
        code_context: str,
        user_level: str = "intermediate"
    ) -> LearningModule:
        """
        Generate comprehensive educational content about a vulnerability.
        
        Args:
            vulnerability: Vulnerability details from scanner
            code_context: Surrounding code for context
            user_level: Target user expertise level
            
        Returns:
            Complete learning module with explanations and exercises
        """
        logger.info(f"Creating learning module for {vulnerability.get('type', 'unknown')} vulnerability")
        
        prompt = self._build_learning_module_prompt(vulnerability, code_context, user_level)
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.7,
                thinking_level=3
            )
            
            module_data = self._parse_learning_module_response(response)
            
            learning_module = LearningModule(
                vulnerability_type=vulnerability.get('type', 'Unknown'),
                severity=vulnerability.get('severity', 'Unknown'),
                location=vulnerability.get('location', 'Unknown'),
                explanation_simple=module_data.get('explanation_simple', ''),
                explanation_technical=module_data.get('explanation_technical', ''),
                attack_scenario=module_data.get('attack_scenario', ''),
                real_world_example=module_data.get('real_world_example', ''),
                remediation_steps=module_data.get('remediation_steps', []),
                quiz_questions=module_data.get('quiz_questions', []),
                additional_resources=module_data.get('resources', [])
            )
            
            logger.info(f"Successfully created learning module")
            return learning_module
            
        except Exception as e:
            logger.error(f"Error creating learning module: {e}")
            raise
    
    def start_interactive_session(
        self,
        session_id: str,
        vulnerability: Dict[str, Any],
        user_level: str = "intermediate"
    ) -> MentorSession:
        """
        Start an interactive Q&A session about a vulnerability.
        
        Args:
            session_id: Unique session identifier
            vulnerability: Vulnerability to discuss
            user_level: User expertise level
            
        Returns:
            Initialized mentor session
        """
        session = MentorSession(
            session_id=session_id,
            vulnerability_focus=vulnerability.get('type', 'Unknown'),
            user_level=user_level,
            interactions=[]
        )
        
        self.sessions[session_id] = session
        
        # Generate opening explanation
        opening = self._generate_session_opening(vulnerability, user_level)
        session.interactions.append({
            'role': 'mentor',
            'content': opening
        })
        
        logger.info(f"Started interactive session {session_id}")
        return session
    
    def ask_question(
        self,
        session_id: str,
        question: str,
        code_snippet: Optional[str] = None
    ) -> str:
        """
        Ask a question during an interactive mentoring session.
        
        Args:
            session_id: Active session ID
            question: User's question
            code_snippet: Optional code context
            
        Returns:
            Mentor's response
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        # Add user question to interaction history
        session.interactions.append({
            'role': 'user',
            'content': question
        })
        
        # Generate contextual response
        response = self._generate_contextual_response(
            session=session,
            question=question,
            code_snippet=code_snippet
        )
        
        # Add mentor response to history
        session.interactions.append({
            'role': 'mentor',
            'content': response
        })
        
        return response
    
    def generate_attack_demonstration(
        self,
        vulnerability: Dict[str, Any],
        code_context: str
    ) -> Dict[str, Any]:
        """
        Generate step-by-step attack demonstration for educational purposes.
        
        Args:
            vulnerability: Vulnerability details
            code_context: Vulnerable code
            
        Returns:
            Detailed attack demonstration with steps and payloads
        """
        logger.info(f"Generating attack demonstration for {vulnerability.get('type', 'unknown')}")
        
        prompt = f"""You are a security educator demonstrating how vulnerabilities can be exploited.

VULNERABILITY:
Type: {vulnerability.get('type', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Location: {vulnerability.get('location', 'Unknown')}

CODE CONTEXT:
{code_context}

Generate a detailed, educational attack demonstration including:

1. ATTACK OVERVIEW
   - What the attacker's goal is
   - What they need to accomplish it

2. STEP-BY-STEP ATTACK PROCESS
   - Each step with detailed explanation
   - Actual payloads or commands that would be used
   - Expected system response at each step

3. POTENTIAL IMPACT
   - What data could be accessed
   - What actions could be performed
   - Business consequences

4. DETECTION METHODS
   - How this attack could be detected
   - What logs would show
   - Warning signs

Format response as JSON with keys: overview, steps (array), impact, detection
Be educational but responsible - emphasize this is for learning purposes only.
"""
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.8,
                thinking_level=4
            )
            
            return self._parse_attack_demonstration(response)
            
        except Exception as e:
            logger.error(f"Error generating attack demonstration: {e}")
            raise
    
    def assess_understanding(
        self,
        session_id: str,
        vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Generate and administer a quiz to assess user understanding.
        
        Args:
            session_id: Active session ID
            vulnerability_type: Type of vulnerability to quiz on
            
        Returns:
            Quiz with questions and scoring rubric
        """
        logger.info(f"Generating assessment for {vulnerability_type}")
        
        prompt = f"""Generate a comprehensive quiz to assess understanding of {vulnerability_type}.

Create 5 questions of varying difficulty:
- 2 multiple choice (basic understanding)
- 2 scenario-based (application of knowledge)
- 1 code review (identify vulnerability in code sample)

For each question provide:
- Question text
- Options (for multiple choice)
- Correct answer
- Detailed explanation of why answer is correct
- Common misconceptions

Format as JSON array of question objects.
"""
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.7,
                thinking_level=2
            )
            
            quiz_data = self._parse_quiz_response(response)
            
            return {
                'session_id': session_id,
                'vulnerability_type': vulnerability_type,
                'questions': quiz_data,
                'total_points': len(quiz_data) * 10
            }
            
        except Exception as e:
            logger.error(f"Error generating assessment: {e}")
            raise
    
    def _build_learning_module_prompt(
        self,
        vulnerability: Dict[str, Any],
        code_context: str,
        user_level: str
    ) -> str:
        """Build comprehensive prompt for learning module generation."""
        return f"""You are an expert security educator creating educational content about a vulnerability.

VULNERABILITY DETAILS:
Type: {vulnerability.get('type', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Description: {vulnerability.get('description', 'No description provided')}
Location: {vulnerability.get('location', 'Unknown')}

CODE CONTEXT:
{code_context}

USER LEVEL: {user_level}

Generate comprehensive educational content with the following sections:

1. SIMPLE EXPLANATION (for non-technical stakeholders)
   - What is this vulnerability in plain language?
   - Why does it matter?
   - Real-world analogy

2. TECHNICAL EXPLANATION (for developers)
   - Technical mechanism of the vulnerability
   - Why the code is vulnerable
   - What attackers can do

3. ATTACK SCENARIO
   - Realistic step-by-step attack walkthrough
   - Actual payloads or techniques
   - Expected outcomes

4. REAL WORLD EXAMPLE
   - Famous breach that involved this vulnerability
   - Impact and consequences
   - Lessons learned

5. REMEDIATION STEPS
   - Specific code changes needed
   - Best practices to prevent recurrence
   - Testing strategies

6. QUIZ QUESTIONS (3 questions)
   - Mix of multiple choice and scenario-based
   - Include answers and explanations

7. ADDITIONAL RESOURCES
   - Links to OWASP, CWE, or other authoritative sources
   - Recommended reading

Format the entire response as JSON with keys matching the sections above.
Be thorough, educational, and actionable. Adjust technical depth for {user_level} level.
"""
    
    def _generate_session_opening(
        self,
        vulnerability: Dict[str, Any],
        user_level: str
    ) -> str:
        """Generate welcoming opening message for interactive session."""
        prompt = f"""Generate a welcoming, educational opening message for an interactive security mentoring session.

VULNERABILITY: {vulnerability.get('type', 'Unknown')}
SEVERITY: {vulnerability.get('severity', 'Unknown')}
USER LEVEL: {user_level}

The message should:
- Welcome the developer
- Briefly explain what we'll be learning about
- Encourage questions
- Be supportive and non-judgmental
- Be 3-4 sentences

Respond with just the message text, no JSON.
"""
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.9,
                thinking_level=1
            )
            return response.strip()
        except Exception as e:
            logger.warning(f"Error generating opening: {e}")
            return f"Welcome! Let's learn about {vulnerability.get('type', 'this vulnerability')}. I'm here to help you understand how it works, why it's dangerous, and how to fix it. Feel free to ask any questions!"
    
    def _generate_contextual_response(
        self,
        session: MentorSession,
        question: str,
        code_snippet: Optional[str]
    ) -> str:
        """Generate contextual response based on conversation history."""
        # Build conversation context
        conversation_history = "\n".join([
            f"{msg['role'].upper()}: {msg['content']}"
            for msg in session.interactions[-5:]  # Last 5 interactions
        ])
        
        code_context = f"\n\nCODE SNIPPET:\n{code_snippet}" if code_snippet else ""
        
        prompt = f"""You are an expert security mentor in an interactive teaching session.

CONVERSATION HISTORY:
{conversation_history}

CURRENT QUESTION:
{question}
{code_context}

CONTEXT:
- Vulnerability focus: {session.vulnerability_focus}
- User level: {session.user_level}

Provide a clear, educational response that:
- Directly answers the question
- Relates to the specific vulnerability we're discussing
- Adjusts technical depth for {session.user_level} level
- Encourages further learning
- Uses examples when helpful
- Is conversational and supportive

Keep response focused and concise (3-5 paragraphs maximum).
Respond with just the answer text, no JSON or formatting.
"""
        
        try:
            response = self.client.generate_content(
                prompt=prompt,
                temperature=0.8,
                thinking_level=3
            )
            return response.strip()
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return "I apologize, but I encountered an error processing your question. Could you please rephrase it?"
    
    def _parse_learning_module_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response for learning module."""
        try:
            # Try to extract JSON from response
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            
            return json.loads(response.strip())
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            # Return structured fallback
            return {
                'explanation_simple': 'A security vulnerability was found in your code.',
                'explanation_technical': response[:500],
                'attack_scenario': 'An attacker could exploit this vulnerability.',
                'real_world_example': 'Similar vulnerabilities have led to data breaches.',
                'remediation_steps': ['Review the code', 'Apply security patches'],
                'quiz_questions': [],
                'resources': []
            }
    
    def _parse_attack_demonstration(self, response: str) -> Dict[str, Any]:
        """Parse attack demonstration response."""
        try:
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            
            return json.loads(response.strip())
        except json.JSONDecodeError:
            return {
                'overview': response[:200],
                'steps': ['Attack demonstration could not be generated'],
                'impact': 'Potential security breach',
                'detection': 'Review security logs'
            }
    
    def _parse_quiz_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse quiz questions response."""
        try:
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            
            data = json.loads(response.strip())
            return data if isinstance(data, list) else data.get('questions', [])
        except json.JSONDecodeError:
            return []
    
    def export_session(self, session_id: str, output_path: str) -> None:
        """
        Export mentoring session to file for future reference.
        
        Args:
            session_id: Session to export
            output_path: File path for export
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        export_data = {
            'session_id': session.session_id,
            'vulnerability_focus': session.vulnerability_focus,
            'user_level': session.user_level,
            'interactions': session.interactions,
            'quiz_score': session.quiz_score,
            'interaction_count': len(session.interactions)
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported session {session_id} to {output_path}")
