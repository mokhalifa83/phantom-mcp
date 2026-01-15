"""
👻 PHANTOM - Session Manager

Manage pentesting sessions and state.
"""

import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from phantom.logger import get_logger

logger = get_logger("phantom.utils.session")


class SessionManager:
    """Manage pentesting sessions."""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        logger.info("Session manager initialized")
    
    def create_session(self, target: str) -> str:
        """
        Create new session.
        
        Args:
            target: Target system
            
        Returns:
            Session ID
        """
        session_id = str(uuid.uuid4())
        
        self.sessions[session_id] = {
            "id": session_id,
            "target": target,
            "created_at": datetime.now().isoformat(),
            "findings": [],
            "scans": [],
        }
        
        logger.info(f"Created session {session_id} for target {target}")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        return self.sessions.get(session_id)
    
    def add_finding(self, session_id: str, finding: Dict[str, Any]) -> None:
        """Add finding to session."""
        if session_id in self.sessions:
            self.sessions[session_id]["findings"].append(finding)
            logger.info(f"Added finding to session {session_id}")
    
    def list_sessions(self) -> list[Dict[str, Any]]:
        """List all sessions."""
        return list(self.sessions.values())
