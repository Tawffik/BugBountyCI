#!/usr/bin/env python3
"""
Unified AI Provider with Multi-Model Fallback

Supports: Groq (free), Gemini (free), OpenRouter (free/paid), Anthropic (paid)
Fallback order: Groq -> Gemini -> OpenRouter -> Anthropic
If ALL fail, returns None gracefully without breaking the pipeline.
"""

import os
import json
import time
import requests
from typing import Optional, Dict, List


class AIProvider:
    """Unified AI interface with automatic fallback"""
    
    # Provider priority: free & fast first
    PROVIDERS = ["groq", "gemini", "openrouter", "anthropic"]
    
    def __init__(self):
        self.api_keys = {
            "groq": os.environ.get("GROQ_API_KEY", ""),
            "gemini": os.environ.get("GEMINI_API_KEY", ""),
            "openrouter": os.environ.get("OPENROUTER_API_KEY", ""),
            "anthropic": os.environ.get("ANTHROPIC_API_KEY", "")
        }
        self.last_successful_provider = None
        self.errors = []
    
    def _call_groq(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """Groq - FREE, very fast, Llama models"""
        api_key = self.api_keys.get("groq")
        if not api_key:
            return None
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 4096
        }
        
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json=data,
                timeout=60
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            else:
                self.errors.append(f"Groq error: {r.status_code} - {r.text[:100]}")
        except Exception as e:
            self.errors.append(f"Groq exception: {e}")
        return None
    
    def _call_gemini(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """Gemini - FREE tier available"""
        api_key = self.api_keys.get("gemini")
        if not api_key:
            return None
        
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        data = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 4096
            }
        }
        
        try:
            r = requests.post(url, json=data, timeout=60)
            if r.status_code == 200:
                return r.json()["candidates"][0]["content"]["parts"][0]["text"]
            else:
                self.errors.append(f"Gemini error: {r.status_code} - {r.text[:100]}")
        except Exception as e:
            self.errors.append(f"Gemini exception: {e}")
        return None
    
    def _call_openrouter(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """OpenRouter - free models available (openrouter/free auto-routes)"""
        api_key = self.api_keys.get("openrouter")
        if not api_key:
            return None
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": "openrouter/free",
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 4096
        }
        
        try:
            r = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/Tawffik/BugBountyCI"
                },
                json=data,
                timeout=60
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            else:
                self.errors.append(f"OpenRouter error: {r.status_code} - {r.text[:100]}")
        except Exception as e:
            self.errors.append(f"OpenRouter exception: {e}")
        return None
    
    def _call_anthropic(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """Anthropic Claude - PAID but highest quality"""
        api_key = self.api_keys.get("anthropic")
        if not api_key:
            return None
        
        messages = []
        if system_prompt:
            messages.append({"role": "user", "content": f"{system_prompt}\n\n{prompt}"})
        else:
            messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": 0.2,
            "messages": messages
        }
        
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json=data,
                timeout=60
            )
            if r.status_code == 200:
                return r.json()["content"][0]["text"]
            else:
                self.errors.append(f"Anthropic error: {r.status_code} - {r.text[:100]}")
        except Exception as e:
            self.errors.append(f"Anthropic exception: {e}")
        return None
    
    def call(self, prompt: str, system_prompt: str = "", retries: int = 1) -> Optional[str]:
        """
        Call AI with automatic fallback through all providers.
        Returns response text or None if all providers fail.
        NEVER raises exceptions - always returns gracefully.
        """
        provider_methods = {
            "groq": self._call_groq,
            "gemini": self._call_gemini,
            "openrouter": self._call_openrouter,
            "anthropic": self._call_anthropic
        }
        
        for attempt in range(retries):
            for provider_name in self.PROVIDERS:
                method = provider_methods[provider_name]
                result = method(prompt, system_prompt)
                
                if result:
                    self.last_successful_provider = provider_name
                    print(f"[AI] ✓ Response from {provider_name} (attempt {attempt + 1})")
                    return result
            
            if attempt < retries - 1:
                print(f"[AI] ⚠ All providers failed on attempt {attempt + 1}, retrying...")
                time.sleep(2)
        
        print("[AI] ✗ All providers failed after all retries")
        if self.errors:
            print(f"[AI] Last errors: {self.errors[-3:]}")
        return None
    
    def call_json(self, prompt: str, system_prompt: str = "") -> Optional[Dict]:
        """Call AI and parse JSON response with fallback"""
        import re
        
        response = self.call(prompt, system_prompt)
        if not response:
            return None
        
        # Try to extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try direct JSON parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            print("[AI] ⚠ Failed to parse JSON from AI response")
            return None
    
    def get_available_providers(self) -> List[str]:
        """Return list of providers with configured API keys"""
        return [p for p in self.PROVIDERS if self.api_keys.get(p)]
    
    def status_report(self) -> str:
        """Human-readable status of AI providers"""
        available = self.get_available_providers()
        if not available:
            return "No AI providers configured (set GROQ_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, or ANTHROPIC_API_KEY)"
        return f"Available AI providers: {', '.join(available)}"


# Global instance for easy access
ai = AIProvider()


def quick_call(prompt: str, system_prompt: str = "") -> Optional[str]:
    """Convenience function for quick AI calls"""
    return ai.call(prompt, system_prompt)


def quick_call_json(prompt: str, system_prompt: str = "") -> Optional[Dict]:
    """Convenience function for quick JSON AI calls"""
    return ai.call_json(prompt, system_prompt)


if __name__ == "__main__":
    print("Testing AI providers...")
    print(ai.status_report())
    
    result = ai.call("Say 'hello' and nothing else")
    if result:
        print(f"Test response: {result[:100]}")
    else:
        print("No response (no providers configured or all failed)")