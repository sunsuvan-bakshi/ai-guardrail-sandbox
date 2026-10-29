"""
Core Guardrail and Prompt Injection Detection Engine
Applies regex heuristics, pattern matching, and risk scoring to incoming text payloads.
"""

import re
from typing import Dict, List, Tuple

class PromptGuardrail:
    def __init__(self, risk_threshold: float = 0.5):
        self.risk_threshold = risk_threshold

        # Define compiled regex patterns for known prompt injection / jailbreak vectors
        self.injection_patterns = [
            # Direct instruction overrides
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"disregard\s+(all\s+)?previous\s+directives",
            r"forget\s+(all\s+)?prior\s+rules",

            # System prompt leaks & extractions
            r"reveal\s+(your\s+)?system\s+prompt",
            r"output\s+your\s+initial\s+instructions",
            r"print\s+system\s+configuration",

            # Persona adoption / Jailbreaks
            r"\bdan\b.*do\s+anything\s+now",
            r"you\s+are\s+now\s+unrestricted",
            r"act\s+as\s+a\s+rogue\s+ai",

            # Delimiter / Injection framing attacks
            r"\[system\s+instruction\]",
            r"<\|im_start\|>system",
        ]

    def analyze(self, text: str) -> Dict:
        """
        Inspects an input string for prompt injection and calculates a risk score.
        Returns a dictionary containing the risk score, status, and matched rules.
        """

        if not text or not isinstance(text, str):
            return {
                "is_safe" : True,
                "risk_score" : 0.0,
                "matched_patterns" : [],
                "reason" : "Empty or invalid string"
            }

        matched_triggers = []
        normalized_text = text.lower()

        # Check against all known injection signatures
        for pattern in self.injection_patterns:
            if re.search(pattern, normalized_text, re.IGNORECASE):
                matched_triggers.append(pattern)

        # Calculate risk score based on the matches where each match adds weight to the score
        risk_score = min(1.0, len(matched_triggers) * 0.5)

        is_safe = risk_score < self.risk_threshold

        return {
            "is_safe" : is_safe,
            "risk_score" : risk_score,
            "matched_patterns" : matched_triggers,
            "reason" : "Blocked due to potential prompt injection signatures" if not is_safe else "Input passed guardrail checks"
        }
