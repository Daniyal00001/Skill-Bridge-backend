# ============================================================
# PATH: backend / ai / moderation / test_moderation.py
# PURPOSE: Test script for AI moderation engine
# ============================================================

import asyncio
import sys
import os

# Add parent dir to path to import shared modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from moderation.moderation_service import ModerationService
from shared.llm_service import LLMService

async def test():
    # Load env vars for API key
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '..', '..', '.env'))

    llm = LLMService()
    mod_svc = ModerationService(llm)

    test_messages = [
        {
            "message": "Hi, I'm interested in your project! Check my portfolio at github.com/test",
            "contract_status": "NONE",
            "user_violation_count": 0
        },
        {
            "message": "Let's discuss further on WhatsApp, my number is +92 300 1234567 or email me at test@gmail.com",
            "contract_status": "NONE",
            "user_violation_count": 0
        },
        {
            "message": "We can continue on Telegram @test_user",
            "contract_status": "NONE",
            "user_violation_count": 3
        },
        {
            "message": "Send me your WhatsApp number.",
            "contract_status": "ACTIVE",
            "user_violation_count": 0
        }
    ]

    print("\n🚀 Starting AI Moderation Engine Tests...\n")
    
    for test_case in test_messages:
        print(f"--- Testing Message: \"{test_case['message']}\" ---")
        print(f"--- Contract: {test_case['contract_status']} | Violations: {test_case['user_violation_count']} ---")
        
        result = await mod_svc.moderate(
            message=test_case['message'],
            contract_status=test_case['contract_status'],
            user_violation_count=test_case['user_violation_count']
        )
        
        print(f"✅ Violation: {result.violation}")
        print(f"🚨 Severity: {result.severity}")
        print(f"🚦 Action: {result.suggested_action}")
        print(f"💬 Sanitized: {result.sanitized_message}")
        print(f"🧐 Reason: {result.reason}")
        print("-" * 50)
        print()

if __name__ == "__main__":
    asyncio.run(test())
