"""
Gemini AI Analyzer for Network Security Threats
Handles all Gemini API interactions with rate limiting and caching
"""
import streamlit as st
import google.generativeai as genai
from datetime import datetime, timedelta
import hashlib
import json
import os
import time
from typing import Dict, Optional, List
import yaml
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class GeminiAnalyzer:
    """Handles Gemini AI analysis for network threats"""
    
    def __init__(self):
        # Configure Gemini
        self.api_key = os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            st.error("❌ GEMINI_API_KEY not found in .env file")
            self.available = False
            return
            
        genai.configure(api_key=self.api_key)
        
        # Load configuration
        self.config = self._load_config()
        
        # Set up models
        self.fast_model = genai.GenerativeModel(
            self.config['gemini']['models']['fast'],
            generation_config=self.config['gemini']['generation_config']
        )
        
        self.powerful_model = genai.GenerativeModel(
            self.config['gemini']['models']['powerful'],
            generation_config=self.config['gemini']['generation_config']
        )
        
        # Rate limiting
        self.rate_limits = self.config['rate_limits']
        self.api_calls = []  # Track API calls for rate limiting
        
        # Cache
        self.cache = {}
        self.cache_config = self.config['cache']
        
        self.available = True
        
        # Test connection
        self._test_connection()
    
    def _load_config(self) -> dict:
        """Load configuration from yaml file"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'config', 'ai_config.yaml'
        )
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            # Fallback to default config
            return {
                'gemini': {
                    'enabled': True,
                    'models': {
                        'fast': os.getenv('GEMINI_FAST_MODEL', 'gemini-1.5-flash'),
                        'powerful': os.getenv('GEMINI_POWERFUL_MODEL', 'gemini-1.5-pro')
                    },
                    'generation_config': {
                        'temperature': 0.3,
                        'max_output_tokens': 500,
                        'top_p': 0.8,
                        'top_k': 40
                    }
                },
                'rate_limits': {
                    'enabled': True,
                    'limits': {
                        'per_minute': int(os.getenv('GEMINI_RATE_LIMIT_MINUTE', 60)),
                        'per_day': int(os.getenv('GEMINI_RATE_LIMIT_DAY', 1500))
                    }
                },
                'cache': {
                    'enabled': True,
                    'ttl': 3600,
                    'max_size': 1000
                }
            }
    
    def _test_connection(self):
        """Test Gemini API connection"""
        try:
            # Simple test prompt
            response = self.fast_model.generate_content("Say 'Connected to Gemini API'")
            if response.text:
                st.success("✅ Gemini AI connected successfully")
        except Exception as e:
            st.error(f"❌ Gemini connection failed: {e}")
            self.available = False
    
    def _check_rate_limit(self) -> tuple[bool, str]:
        """Check if we're within rate limits"""
        if not self.rate_limits['enabled']:
            return True, "OK"
        
        now = datetime.now()
        
        # Clean up old entries
        self.api_calls = [
            ts for ts in self.api_calls 
            if (now - ts).seconds < 60 or ts.date() == now.date()
        ]
        
        # Count calls in last minute
        minute_calls = sum(1 for ts in self.api_calls if (now - ts).seconds < 60)
        day_calls = sum(1 for ts in self.api_calls if ts.date() == now.date())
        
        limits = self.rate_limits['limits']
        
        if minute_calls >= limits['per_minute']:
            return False, f"Rate limit: {limits['per_minute']} per minute"
        
        if day_calls >= limits['per_day']:
            return False, f"Daily limit: {limits['per_day']} per day"
        
        return True, "OK"
    
    def _get_cache_key(self, threat_data: Dict) -> str:
        """Generate cache key from threat data"""
        # Create a unique key based on threat characteristics
        key_parts = [
            threat_data.get('attack_type', 'unknown'),
            threat_data.get('threat_level', 'unknown'),
            str(threat_data.get('confidence', 0)),
            str(threat_data.get('layer0_flagged', False)),
            str(threat_data.get('layer1_flagged', False)),
        ]
        
        # Add flow details if available
        flow = threat_data.get('flow_details', {})
        key_parts.extend([
            flow.get('protocol', 'unknown'),
            str(flow.get('dst_port', 'unknown')),
            flow.get('src_ip', 'unknown')[:10]  # First 10 chars of IP for uniqueness
        ])
        
        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_from_cache(self, cache_key: str) -> Optional[Dict]:
        """Get analysis from cache if valid"""
        if not self.cache_config['enabled']:
            return None
        
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            age = (datetime.now() - cached['timestamp']).seconds
            
            if age < self.cache_config['ttl']:
                cached['from_cache'] = True
                return cached
        
        return None
    
    def _save_to_cache(self, cache_key: str, analysis: Dict):
        """Save analysis to cache"""
        if not self.cache_config['enabled']:
            return
        
        # Manage cache size
        if len(self.cache) >= self.cache_config['max_size']:
            # Remove oldest entry
            oldest_key = min(self.cache.keys(), 
                           key=lambda k: self.cache[k]['timestamp'])
            del self.cache[oldest_key]
        
        analysis['timestamp'] = datetime.now()
        analysis['from_cache'] = False
        self.cache[cache_key] = analysis
    
    def _create_analysis_prompt(self, threat_data: Dict, detailed: bool = False) -> str:
        """Create prompt for Gemini based on threat data"""
        flow = threat_data.get('flow_details', {})
        
        # Base prompt with threat details
        prompt = f"""You are a network security analyst at a SOC (Security Operations Center). Analyze this network threat and provide a concise, actionable analysis:

THREAT CLASSIFICATION: {threat_data.get('attack_type', 'Unknown')}
THREAT LEVEL: {threat_data.get('threat_level', 'INFO')}
CONFIDENCE: {threat_data.get('confidence', 0)*100:.1f}%

NETWORK FLOW DETAILS:
- Source IP: {flow.get('src_ip', 'N/A')}
- Source Port: {flow.get('src_port', 'N/A')}
- Destination IP: {flow.get('dst_ip', 'N/A')}
- Destination Port: {flow.get('dst_port', 'N/A')}
- Protocol: {flow.get('protocol', 'N/A')}
- Bytes Transfered: {flow.get('bytes', 'N/A')}
- Packet Count: {flow.get('packets', 'N/A')}

DETECTION LAYERS:
- Layer 0 (Anomaly Detection): {'⚠️ ANOMALY DETECTED' if threat_data.get('layer0_flagged') else '✅ Normal'}
- Layer 1 (Attack Classification): {'🔴 ATTACK CONFIRMED' if threat_data.get('layer1_flagged') else '✅ Normal'}

"""
        
        if detailed:
            prompt += """Provide a comprehensive analysis including:

1. THREAT ANALYSIS (2-3 sentences)
   - What type of attack is this?
   - Why was it flagged?

2. IMPACT ASSESSMENT (1-2 sentences)
   - What could this mean for the network?
   - Potential damage or data at risk?

3. IMMEDIATE ACTIONS (3 bullet points)
   - What should the analyst do right now?
   - Specific remediation steps

4. MITRE ATT&CK MAPPING
   - Technique ID and name if applicable

5. ADDITIONAL CONTEXT
   - Is this part of a larger pattern?
   - Any related indicators to watch?

Keep it technical but actionable for a SOC analyst."""
        else:
            prompt += """Provide a brief analysis (2-3 sentences) covering:
- What this threat means
- Immediate risk level
- One recommended action

Keep it concise and actionable."""
        
        return prompt
    
    def analyze(self, threat_data: Dict, detailed: bool = False) -> Dict:
        """
        Analyze a threat using Gemini AI
        
        Args:
            threat_data: Dictionary with threat information
            detailed: Whether to use powerful model for detailed analysis
            
        Returns:
            Dictionary with analysis results
        """
        if not self.available:
            return {
                'success': False,
                'error': 'Gemini AI not available',
                'source': 'gemini'
            }
        
        # Check cache first
        cache_key = self._get_cache_key(threat_data)
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        
        # Check rate limit
        allowed, message = self._check_rate_limit()
        if not allowed:
            return {
                'success': False,
                'error': f'Rate limit exceeded: {message}',
                'source': 'rate_limit'
            }
        
        try:
            # Choose model based on detail level
            model = self.powerful_model if detailed else self.fast_model
            
            # Create prompt
            prompt = self._create_analysis_prompt(threat_data, detailed)
            
            # Track API call
            self.api_calls.append(datetime.now())
            
            # Generate analysis
            response = model.generate_content(prompt)
            
            if response and response.text:
                result = {
                    'success': True,
                    'analysis': response.text,
                    'model': model.model_name,
                    'detailed': detailed,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'gemini'
                }
                
                # Save to cache
                self._save_to_cache(cache_key, result)
                
                return result
            else:
                return {
                    'success': False,
                    'error': 'Empty response from Gemini',
                    'source': 'gemini'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'source': 'gemini'
            }
    
    def get_status(self) -> Dict:
        """Get current status of the analyzer"""
        now = datetime.now()
        
        # Clean up old entries for accurate counting
        self.api_calls = [
            ts for ts in self.api_calls 
            if (now - ts).seconds < 60 or ts.date() == now.date()
        ]
        
        minute_calls = sum(1 for ts in self.api_calls if (now - ts).seconds < 60)
        day_calls = sum(1 for ts in self.api_calls if ts.date() == now.date())
        
        limits = self.rate_limits['limits']
        
        return {
            'available': self.available,
            'api_calls_minute': minute_calls,
            'api_calls_day': day_calls,
            'limit_minute': limits['per_minute'],
            'limit_day': limits['per_day'],
            'remaining_minute': limits['per_minute'] - minute_calls,
            'remaining_day': limits['per_day'] - day_calls,
            'cache_size': len(self.cache),
            'models': {
                'fast': self.config['gemini']['models']['fast'],
                'powerful': self.config['gemini']['models']['powerful']
            }
        }
    
    def clear_cache(self):
        """Clear the analysis cache"""
        self.cache.clear()
        return True

# Singleton instance for use across the app
@st.cache_resource
def get_gemini_analyzer():
    """Get or create GeminiAnalyzer singleton"""
    return GeminiAnalyzer()