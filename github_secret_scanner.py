import requests
import re
import base64
from github import Github
import yaml
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║           GitHub Secret Scanner           ║
    ║      Find exposed secrets and tokens      ║
    ╚═══════════════════════════════════════════╝
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

class GitHubSecretScanner:
    def __init__(self, github_token):
        self.github_token = github_token
        self.g = Github(github_token)
        
        # Common patterns for secrets
        self.secret_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret': r'[0-9a-zA-Z/+]{40}',
            'Private Key': r'-----BEGIN PRIVATE KEY-----',
            'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
            'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36}',
            'Generic API Key': r'[aA][pP][iI]_?[kK][eE][yY].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
            'Generic Secret': r'[sS][eE][cC][rR][eE][tT].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
            'Password in URL': r'[a-zA-Z]{3,10}://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*'
        }

    def search_github(self, keyword, max_repos=10):
        """Search GitHub repositories for a specific keyword"""
        print(f"\n{Fore.YELLOW}🔍 Searching for repositories containing '{keyword}'...{Style.RESET_ALL}")
        results = []
        
        try:
            repositories = self.g.search_repositories(query=keyword, sort='stars')
            for repo in repositories[:max_repos]:
                print(f"\n{Fore.BLUE}📁 Analyzing repository: {repo.full_name}{Style.RESET_ALL}")
                secrets_found = self.scan_repository(repo)
                if secrets_found:
                    results.append({
                        'repository': repo.full_name,
                        'url': repo.html_url,
                        'secrets': secrets_found
                    })
        except Exception as e:
            print(f"{Fore.RED}❌ Error searching repositories: {str(e)}{Style.RESET_ALL}")
        
        return results

    def scan_repository(self, repo):
        """Scan a repository for potential secrets"""
        secrets_found = []
        
        try:
            contents = repo.get_contents("")
            while contents:
                file_content = contents.pop(0)
                
                if file_content.type == "dir":
                    contents.extend(repo.get_contents(file_content.path))
                else:
                    if self._should_scan_file(file_content.name):
                        file_secrets = self._scan_file_content(file_content)
                        if file_secrets:
                            secrets_found.append({
                                'file': file_content.path,
                                'matches': file_secrets
                            })
                            print(f"{Fore.RED}⚠️  Found potential secrets in: {file_content.path}{Style.RESET_ALL}")
                            
        except Exception as e:
            print(f"{Fore.RED}❌ Error scanning repository: {str(e)}{Style.RESET_ALL}")
            
        return secrets_found

    def _should_scan_file(self, filename):
        """Check if the file should be scanned based on its extension"""
        skip_extensions = {'.jpg', '.png', '.gif', '.mp4', '.zip', '.pdf'}
        return not any(filename.lower().endswith(ext) for ext in skip_extensions)

    def _scan_file_content(self, file_content):
        """Scan file content for potential secrets"""
        matches = {}
        
        try:
            # Get raw content
            raw_content = base64.b64decode(file_content.content).decode('utf-8')
            
            # Check for matches
            for pattern_name, pattern in self.secret_patterns.items():
                findings = re.findall(pattern, raw_content)
                if findings:
                    matches[pattern_name] = len(findings)
                    
        except Exception as e:
            print(f"{Fore.RED}❌ Error scanning file {file_content.path}: {str(e)}{Style.RESET_ALL}")
            
        return matches if matches else None

def print_results_summary(results):
    """Print a structured summary of the results"""
    if not results:
        print(f"\n{Fore.GREEN}✅ No secrets found in scanned repositories.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.YELLOW}📊 Scan Results Summary:{Style.RESET_ALL}")
    print("=" * 60)
    
    for result in results:
        print(f"\n{Fore.CYAN}Repository: {result['repository']}{Style.RESET_ALL}")
        print(f"URL: {result['url']}")
        print("\nSecrets found:")
        
        for secret in result['secrets']:
            print(f"\n📄 File: {secret['file']}")
            print("   Matches found:")
            for secret_type, count in secret['matches'].items():
                print(f"   - {secret_type}: {count} occurrence(s)")
        
        print("-" * 60)

def main():
    # Display banner
    print_banner()
    
    # Get GitHub token from environment variable
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        print(f"{Fore.RED}❌ Please set your GITHUB_TOKEN environment variable{Style.RESET_ALL}")
        return

    scanner = GitHubSecretScanner(github_token)
    
    # Get search keyword from user
    print(f"\n{Fore.CYAN}Enter search details:{Style.RESET_ALL}")
    keyword = input("🔍 Keyword to search (e.g., 'company_name'): ")
    max_repos = int(input("📚 Maximum number of repositories to scan (default 10): ") or 10)
    
    # Perform the search
    results = scanner.search_github(keyword, max_repos)
    
    # Print structured results to terminal
    print_results_summary(results)
    
    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"scan_results_{timestamp}.yaml"
    
    with open(output_file, 'w') as f:
        yaml.dump(results, f, default_flow_style=False)
    
    print(f"\n{Fore.GREEN}✅ Results have been saved to: {output_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 