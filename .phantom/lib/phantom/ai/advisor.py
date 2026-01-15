"""
👻 PHANTOM - Pentest Advisor

AI-powered penetration testing advisor using Google Gemini.
"""

import os
import google.generativeai as genai
from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.ai.advisor")


class PentestAdvisor:
    """AI pentesting advisor."""
    
    def __init__(self, config: PhantomConfig):
        self.config = config
        api_key = os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            logger.warning("GEMINI_API_KEY not set")
            self.model = None
        else:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(config.ai.model)
        
        logger.info("Pentest advisor initialized")
    
    async def get_advice(self, query: str) -> str:
        """Get pentesting advice from AI."""
        if not self.model:
            return "AI features not available - GEMINI_API_KEY not set"
        
        logger.info(f"Getting advice for: {query}")
        
        try:
            response = self.model.generate_content(
                f"As a senior penetration tester, provide advice on: {query}",
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=2048,
                    temperature=self.config.ai.temperature,
                )
            )
            
            return response.text
        
        except Exception as e:
            logger.error(f"Advice generation failed: {e}")
            return f"Error: {str(e)}"
