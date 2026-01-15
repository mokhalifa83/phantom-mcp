"""
👻 PHANTOM - Security Analyzer

AI-powered vulnerability analysis using Google Gemini.
"""

import os
from typing import Dict, Any, List
import google.generativeai as genai
from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.ai.analyzer")


class SecurityAnalyzer:
    """AI-powered security analysis."""
    
    def __init__(self, config: PhantomConfig):
        self.config = config
        api_key = os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            logger.warning("GEMINI_API_KEY not set - AI features disabled")
            self.model = None
        else:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(config.ai.model)
        
        logger.info("Security analyzer initialized")
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using AI.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            AI analysis with prioritization and recommendations
        """
        if not self.model:
            return {"error": "AI features not available - GEMINI_API_KEY not set"}
        
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities with AI")
        
        # Prepare prompt
        vuln_summary = "\n".join([
            f"- {v.get('type', 'Unknown')}: {v.get('description', 'No description')}"
            for v in vulnerabilities
        ])
        
        prompt = f"""You are a senior penetration tester analyzing security findings.

Vulnerabilities found:
{vuln_summary}

Please provide:
1. Risk assessment and prioritization
2. Potential impact analysis
3. Exploitation difficulty
4. Recommended remediation steps
5. Business impact summary

Format your response as a structured security analysis."""
        
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=self.config.ai.max_tokens,
                    temperature=self.config.ai.temperature,
                )
            )
            
            analysis = response.text
            
            logger.info("AI analysis completed")
            
            return {
                "analysis": analysis,
                "model": self.config.ai.model,
                "vulnerabilities_analyzed": len(vulnerabilities),
            }
        
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {"error": str(e)}
    
    async def suggest_exploitation(
        self,
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get AI suggestions for exploiting a vulnerability.
        
        Args:
            vulnerability: Vulnerability details
            
        Returns:
            Exploitation suggestions
        """
        if not self.model:
            return {"error": "AI features not available - GEMINI_API_KEY not set"}
        
        logger.info("Getting exploitation suggestions from AI")
        
        prompt = f"""As an ethical penetration tester, provide exploitation guidance for:

Vulnerability: {vulnerability.get('type')}
Description: {vulnerability.get('description')}
Severity: {vulnerability.get('severity')}

Provide:
1. Exploitation approach
2. Required tools
3. Potential payloads
4. Defense evasion techniques
5. Success indicators

⚠️  Remember: This is for authorized security testing only."""
        
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=2048,
                    temperature=self.config.ai.temperature,
                )
            )
            
            return {
                "suggestions": response.text,
                "model": self.config.ai.model,
            }
        
        except Exception as e:
            logger.error(f"Exploitation suggestion failed: {e}")
            return {"error": str(e)}
