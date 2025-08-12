"""
Repository Cloner Lambda - Clones repositories for security scanning
"""
import os
import json
import boto3
import logging
import shutil
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import hashlib
import tempfile
from urllib.parse import urlparse
import re

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
secretsmanager = boto3.client('secretsmanager')
ssm_client = boto3.client('ssm')
efs_client = boto3.client('elasticfilesystem')

# Environment variables
CLONE_BUCKET = os.environ.get('CLONE_BUCKET')
EFS_MOUNT_PATH = os.environ.get('EFS_MOUNT_PATH', '/mnt/efs')
MAX_REPO_SIZE_MB = int(os.environ.get('MAX_REPO_SIZE_MB', '1000'))
GITHUB_TOKEN_SECRET = os.environ.get('GITHUB_TOKEN_SECRET')
GITLAB_TOKEN_SECRET = os.environ.get('GITLAB_TOKEN_SECRET')
BITBUCKET_TOKEN_SECRET = os.environ.get('BITBUCKET_TOKEN_SECRET')


class RepositoryCloner:
    """Handles repository cloning for security scanning"""
    
    def __init__(self):
        self.credentials_cache = {}
        self.clone_strategies = {
            'github.com': self._clone_github,
            'gitlab.com': self._clone_gitlab,
            'bitbucket.org': self._clone_bitbucket,
            'codecommit': self._clone_codecommit
        }
        
    def clone_repository(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Clone repository for scanning
        
        Supports:
        1. GitHub (public/private)
        2. GitLab (public/private)
        3. Bitbucket (public/private)
        4. AWS CodeCommit
        5. Generic Git repositories
        """
        
        repository_url = event.get('repository_url')
        branch = event.get('branch', 'main')
        commit_hash = event.get('commit_hash')
        scan_id = event.get('scan_id', self._generate_scan_id(repository_url))
        clone_depth = event.get('clone_depth', 1)  # Shallow clone by default
        include_submodules = event.get('include_submodules', False)
        
        if not repository_url:
            raise ValueError("repository_url is required")
        
        # Parse repository URL
        repo_info = self._parse_repository_url(repository_url)
        
        # Determine clone location
        clone_location = self._determine_clone_location(scan_id, repo_info)
        
        try:
            # Clone repository
            clone_result = self._clone_repository(
                repo_info=repo_info,
                branch=branch,
                commit_hash=commit_hash,
                clone_location=clone_location,
                clone_depth=clone_depth,
                include_submodules=include_submodules
            )
            
            # Validate clone
            validation = self._validate_clone(clone_location, repo_info)
            
            # Analyze repository
            analysis = self._analyze_repository(clone_location)
            
            # Create clone manifest
            manifest = self._create_clone_manifest(
                scan_id=scan_id,
                repo_info=repo_info,
                clone_result=clone_result,
                validation=validation,
                analysis=analysis
            )
            
            # Upload to S3 if needed
            if CLONE_BUCKET and event.get('upload_to_s3', False):
                s3_location = self._upload_to_s3(scan_id, clone_location)
                manifest['s3_location'] = s3_location
            
            return {
                'statusCode': 200,
                'scan_id': scan_id,
                'clone_location': clone_location,
                'repository': repo_info['repository'],
                'branch': branch,
                'commit': clone_result.get('commit_hash'),
                'size_mb': validation['size_mb'],
                'file_count': validation['file_count'],
                'analysis': analysis,
                'manifest': manifest
            }
            
        except Exception as e:
            logger.error(f"Repository clone failed: {e}", exc_info=True)
            
            # Clean up on failure
            self._cleanup_clone(clone_location)
            
            return {
                'statusCode': 500,
                'error': str(e),
                'repository': repository_url
            }
    
    def _parse_repository_url(self, url: str) -> Dict[str, Any]:
        """Parse repository URL to extract components"""
        
        # Handle SSH URLs
        ssh_pattern = r'git@([^:]+):([^/]+)/(.+?)(?:\.git)?$'
        ssh_match = re.match(ssh_pattern, url)
        
        if ssh_match:
            return {
                'url': url,
                'host': ssh_match.group(1),
                'owner': ssh_match.group(2),
                'repository': ssh_match.group(3),
                'protocol': 'ssh',
                'provider': self._identify_provider(ssh_match.group(1))
            }
        
        # Handle HTTPS URLs
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 2:
            owner = path_parts[0]
            repo = path_parts[1].replace('.git', '')
        else:
            owner = 'unknown'
            repo = path_parts[0] if path_parts else 'unknown'
        
        return {
            'url': url,
            'host': parsed.hostname,
            'owner': owner,
            'repository': repo,
            'protocol': parsed.scheme,
            'provider': self._identify_provider(parsed.hostname)
        }
    
    def _identify_provider(self, hostname: str) -> str:
        """Identify git provider from hostname"""
        if not hostname:
            return 'generic'
        
        hostname = hostname.lower()
        
        if 'github' in hostname:
            return 'github'
        elif 'gitlab' in hostname:
            return 'gitlab'
        elif 'bitbucket' in hostname:
            return 'bitbucket'
        elif 'codecommit' in hostname:
            return 'codecommit'
        else:
            return 'generic'
    
    def _determine_clone_location(self, scan_id: str, repo_info: Dict) -> str:
        """Determine where to clone the repository"""
        
        # Use EFS if available for large repos
        if os.path.exists(EFS_MOUNT_PATH) and os.access(EFS_MOUNT_PATH, os.W_OK):
            base_path = os.path.join(EFS_MOUNT_PATH, 'repos')
        else:
            # Use /tmp for Lambda
            base_path = '/tmp/repos'
        
        # Create directory structure
        clone_path = os.path.join(
            base_path,
            repo_info['owner'],
            repo_info['repository'],
            scan_id
        )
        
        # Ensure directory exists
        os.makedirs(clone_path, exist_ok=True)
        
        return clone_path
    
    def _clone_repository(self, 
                         repo_info: Dict,
                         branch: str,
                         commit_hash: Optional[str],
                         clone_location: str,
                         clone_depth: int,
                         include_submodules: bool) -> Dict[str, Any]:
        """Clone repository using appropriate method"""
        
        provider = repo_info['provider']
        
        # Get clone function for provider
        clone_func = self.clone_strategies.get(
            provider,
            self._clone_generic
        )
        
        # Clone repository
        result = clone_func(
            repo_info=repo_info,
            branch=branch,
            clone_location=clone_location,
            clone_depth=clone_depth
        )
        
        # Checkout specific commit if provided
        if commit_hash:
            self._checkout_commit(clone_location, commit_hash)
            result['commit_hash'] = commit_hash
        else:
            # Get current commit hash
            result['commit_hash'] = self._get_current_commit(clone_location)
        
        # Clone submodules if requested
        if include_submodules:
            self._clone_submodules(clone_location)
            result['submodules_cloned'] = True
        
        return result
    
    def _clone_github(self, repo_info: Dict, branch: str, clone_location: str, clone_depth: int) -> Dict[str, Any]:
        """Clone GitHub repository"""
        
        url = repo_info['url']
        
        # Add authentication if private repo
        if self._is_private_repo(repo_info):
            token = self._get_github_token()
            if token:
                # Modify URL to include token
                if repo_info['protocol'] == 'https':
                    parsed = urlparse(url)
                    url = f"{parsed.scheme}://{token}@{parsed.netloc}{parsed.path}"
        
        # Clone repository
        return self._git_clone(url, clone_location, branch, clone_depth)
    
    def _clone_gitlab(self, repo_info: Dict, branch: str, clone_location: str, clone_depth: int) -> Dict[str, Any]:
        """Clone GitLab repository"""
        
        url = repo_info['url']
        
        # Add authentication if private repo
        if self._is_private_repo(repo_info):
            token = self._get_gitlab_token()
            if token:
                if repo_info['protocol'] == 'https':
                    parsed = urlparse(url)
                    url = f"{parsed.scheme}://oauth2:{token}@{parsed.netloc}{parsed.path}"
        
        return self._git_clone(url, clone_location, branch, clone_depth)
    
    def _clone_bitbucket(self, repo_info: Dict, branch: str, clone_location: str, clone_depth: int) -> Dict[str, Any]:
        """Clone Bitbucket repository"""
        
        url = repo_info['url']
        
        # Add authentication if private repo
        if self._is_private_repo(repo_info):
            token = self._get_bitbucket_token()
            if token:
                if repo_info['protocol'] == 'https':
                    # Bitbucket uses app passwords
                    parsed = urlparse(url)
                    url = f"{parsed.scheme}://x-token-auth:{token}@{parsed.netloc}{parsed.path}"
        
        return self._git_clone(url, clone_location, branch, clone_depth)
    
    def _clone_codecommit(self, repo_info: Dict, branch: str, clone_location: str, clone_depth: int) -> Dict[str, Any]:
        """Clone AWS CodeCommit repository"""
        
        # CodeCommit uses AWS credentials
        # Configure git to use AWS credential helper
        self._configure_codecommit_credentials()
        
        return self._git_clone(repo_info['url'], clone_location, branch, clone_depth)
    
    def _clone_generic(self, repo_info: Dict, branch: str, clone_location: str, clone_depth: int) -> Dict[str, Any]:
        """Clone generic Git repository"""
        return self._git_clone(repo_info['url'], clone_location, branch, clone_depth)
    
    def _git_clone(self, url: str, location: str, branch: str, depth: int) -> Dict[str, Any]:
        """Execute git clone command"""
        
        # Build clone command
        cmd = ['git', 'clone']
        
        # Add depth for shallow clone
        if depth > 0:
            cmd.extend(['--depth', str(depth)])
        
        # Add branch
        cmd.extend(['--branch', branch])
        
        # Add URL and destination
        cmd.extend([url, location])
        
        # Set environment for git
        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'  # Disable password prompts
        
        try:
            # Execute clone
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            
            return {
                'status': 'success',
                'clone_time': datetime.utcnow().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            raise Exception("Repository clone timed out after 5 minutes")
        except Exception as e:
            logger.error(f"Git clone error: {e}")
            raise
    
    def _checkout_commit(self, repo_path: str, commit_hash: str):
        """Checkout specific commit"""
        
        cmd = ['git', 'checkout', commit_hash]
        
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise Exception(f"Failed to checkout commit {commit_hash}: {result.stderr}")
    
    def _get_current_commit(self, repo_path: str) -> str:
        """Get current commit hash"""
        
        cmd = ['git', 'rev-parse', 'HEAD']
        
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        
        return 'unknown'
    
    def _clone_submodules(self, repo_path: str):
        """Clone git submodules"""
        
        cmd = ['git', 'submodule', 'update', '--init', '--recursive']
        
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            logger.warning(f"Submodule clone warning: {result.stderr}")
    
    def _is_private_repo(self, repo_info: Dict) -> bool:
        """Check if repository is private (heuristic)"""
        
        # Try to access without credentials first
        url = repo_info['url']
        
        # For SSH URLs, assume private
        if repo_info['protocol'] == 'ssh':
            return True
        
        # For HTTPS, try a quick check
        # In production, implement proper check
        return True  # Assume private for safety
    
    def _get_github_token(self) -> Optional[str]:
        """Get GitHub access token"""
        
        if 'github_token' in self.credentials_cache:
            return self.credentials_cache['github_token']
        
        if GITHUB_TOKEN_SECRET:
            try:
                response = secretsmanager.get_secret_value(
                    SecretId=GITHUB_TOKEN_SECRET
                )
                secret = json.loads(response['SecretString'])
                token = secret.get('token') or secret.get('access_token')
                self.credentials_cache['github_token'] = token
                return token
            except Exception as e:
                logger.error(f"Failed to get GitHub token: {e}")
        
        return None
    
    def _get_gitlab_token(self) -> Optional[str]:
        """Get GitLab access token"""
        
        if 'gitlab_token' in self.credentials_cache:
            return self.credentials_cache['gitlab_token']
        
        if GITLAB_TOKEN_SECRET:
            try:
                response = secretsmanager.get_secret_value(
                    SecretId=GITLAB_TOKEN_SECRET
                )
                secret = json.loads(response['SecretString'])
                token = secret.get('token') or secret.get('access_token')
                self.credentials_cache['gitlab_token'] = token
                return token
            except Exception as e:
                logger.error(f"Failed to get GitLab token: {e}")
        
        return None
    
    def _get_bitbucket_token(self) -> Optional[str]:
        """Get Bitbucket app password"""
        
        if 'bitbucket_token' in self.credentials_cache:
            return self.credentials_cache['bitbucket_token']
        
        if BITBUCKET_TOKEN_SECRET:
            try:
                response = secretsmanager.get_secret_value(
                    SecretId=BITBUCKET_TOKEN_SECRET
                )
                secret = json.loads(response['SecretString'])
                token = secret.get('app_password') or secret.get('token')
                self.credentials_cache['bitbucket_token'] = token
                return token
            except Exception as e:
                logger.error(f"Failed to get Bitbucket token: {e}")
        
        return None
    
    def _configure_codecommit_credentials(self):
        """Configure AWS CodeCommit credentials"""
        
        # Set up git to use AWS credential helper
        subprocess.run([
            'git', 'config', '--global', 'credential.helper',
            '!aws codecommit credential-helper $@'
        ])
        
        subprocess.run([
            'git', 'config', '--global', 'credential.UseHttpPath', 'true'
        ])
    
    def _validate_clone(self, clone_location: str, repo_info: Dict) -> Dict[str, Any]:
        """Validate cloned repository"""
        
        validation = {
            'valid': True,
            'issues': []
        }
        
        # Check if directory exists
        if not os.path.exists(clone_location):
            validation['valid'] = False
            validation['issues'].append('Clone directory does not exist')
            return validation
        
        # Check if it's a git repository
        git_dir = os.path.join(clone_location, '.git')
        if not os.path.exists(git_dir):
            validation['valid'] = False
            validation['issues'].append('Not a valid git repository')
            return validation
        
        # Calculate repository size
        size_mb = self._calculate_directory_size(clone_location) / (1024 * 1024)
        validation['size_mb'] = round(size_mb, 2)
        
        # Check size limit
        if size_mb > MAX_REPO_SIZE_MB:
            validation['valid'] = False
            validation['issues'].append(f'Repository size {size_mb}MB exceeds limit {MAX_REPO_SIZE_MB}MB')
        
        # Count files
        file_count = self._count_files(clone_location)
        validation['file_count'] = file_count
        
        # Check for suspicious patterns
        suspicious = self._check_suspicious_patterns(clone_location)
        if suspicious:
            validation['warnings'] = suspicious
        
        return validation
    
    def _analyze_repository(self, clone_location: str) -> Dict[str, Any]:
        """Analyze cloned repository structure"""
        
        analysis = {
            'languages': {},
            'frameworks': [],
            'has_tests': False,
            'has_ci': False,
            'dependencies': {},
            'security_files': []
        }
        
        # Detect programming languages
        language_files = {
            'python': ['.py'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'java': ['.java'],
            'go': ['.go'],
            'ruby': ['.rb'],
            'php': ['.php'],
            'csharp': ['.cs'],
            'cpp': ['.cpp', '.cc', '.cxx', '.hpp'],
            'rust': ['.rs']
        }
        
        for root, dirs, files in os.walk(clone_location):
            # Skip .git directory
            if '.git' in root:
                continue
            
            for file in files:
                # Language detection
                ext = os.path.splitext(file)[1].lower()
                for lang, extensions in language_files.items():
                    if ext in extensions:
                        analysis['languages'][lang] = analysis['languages'].get(lang, 0) + 1
                
                # Framework detection
                if file == 'package.json':
                    analysis['frameworks'].append('nodejs')
                    analysis['dependencies']['npm'] = self._parse_package_json(
                        os.path.join(root, file)
                    )
                elif file == 'requirements.txt':
                    analysis['frameworks'].append('python')
                    analysis['dependencies']['pip'] = self._parse_requirements_txt(
                        os.path.join(root, file)
                    )
                elif file == 'pom.xml':
                    analysis['frameworks'].append('maven')
                elif file == 'build.gradle':
                    analysis['frameworks'].append('gradle')
                elif file == 'go.mod':
                    analysis['frameworks'].append('go')
                elif file == 'Gemfile':
                    analysis['frameworks'].append('ruby')
                elif file == 'composer.json':
                    analysis['frameworks'].append('php')
                
                # Check for tests
                if 'test' in file.lower() or 'spec' in file.lower():
                    analysis['has_tests'] = True
                
                # Check for CI/CD
                if file in ['.travis.yml', 'Jenkinsfile', '.gitlab-ci.yml', '.circleci/config.yml']:
                    analysis['has_ci'] = True
                
                # Security files
                if file in ['SECURITY.md', '.security.yml', 'security.txt']:
                    analysis['security_files'].append(file)
            
            # Check for GitHub Actions
            if '.github/workflows' in root:
                analysis['has_ci'] = True
                analysis['frameworks'].append('github-actions')
        
        # Calculate language percentages
        total_files = sum(analysis['languages'].values())
        if total_files > 0:
            analysis['language_percentages'] = {
                lang: round(count / total_files * 100, 1)
                for lang, count in analysis['languages'].items()
            }
        
        return analysis
    
    def _create_clone_manifest(self,
                             scan_id: str,
                             repo_info: Dict,
                             clone_result: Dict,
                             validation: Dict,
                             analysis: Dict) -> Dict[str, Any]:
        """Create manifest for cloned repository"""
        
        manifest = {
            'scan_id': scan_id,
            'repository': {
                'url': repo_info['url'],
                'provider': repo_info['provider'],
                'owner': repo_info['owner'],
                'name': repo_info['repository']
            },
            'clone_info': {
                'timestamp': clone_result.get('clone_time', datetime.utcnow().isoformat()),
                'commit_hash': clone_result.get('commit_hash', 'unknown'),
                'submodules_cloned': clone_result.get('submodules_cloned', False)
            },
            'validation': validation,
            'analysis': analysis,
            'metadata': {
                'cloner_version': '1.0',
                'lambda_request_id': os.environ.get('AWS_REQUEST_ID', 'unknown')
            }
        }
        
        return manifest
    
    def _upload_to_s3(self, scan_id: str, clone_location: str) -> str:
        """Upload cloned repository to S3"""
        
        # Create tar archive
        archive_path = f"/tmp/{scan_id}.tar.gz"
        
        try:
            # Create compressed archive
            subprocess.run([
                'tar', '-czf', archive_path,
                '-C', os.path.dirname(clone_location),
                os.path.basename(clone_location)
            ], check=True)
            
            # Upload to S3
            s3_key = f"repos/{scan_id}/repository.tar.gz"
            
            with open(archive_path, 'rb') as f:
                s3_client.put_object(
                    Bucket=CLONE_BUCKET,
                    Key=s3_key,
                    Body=f,
                    ServerSideEncryption='AES256'
                )
            
            # Clean up archive
            os.remove(archive_path)
            
            return f"s3://{CLONE_BUCKET}/{s3_key}"
            
        except Exception as e:
            logger.error(f"Failed to upload to S3: {e}")
            raise
    
    def _cleanup_clone(self, clone_location: str):
        """Clean up cloned repository"""
        
        try:
            if os.path.exists(clone_location):
                shutil.rmtree(clone_location)
        except Exception as e:
            logger.error(f"Failed to cleanup clone: {e}")
    
    def _generate_scan_id(self, repository_url: str) -> str:
        """Generate unique scan ID"""
        
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        url_hash = hashlib.md5(repository_url.encode()).hexdigest()[:8]
        
        return f"scan-{timestamp}-{url_hash}"
    
    def _calculate_directory_size(self, path: str) -> int:
        """Calculate total size of directory in bytes"""
        
        total_size = 0
        
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except:
                    pass
        
        return total_size
    
    def _count_files(self, path: str) -> int:
        """Count total files in directory"""
        
        count = 0
        
        for dirpath, dirnames, filenames in os.walk(path):
            # Skip .git directory
            if '.git' in dirpath:
                continue
            count += len(filenames)
        
        return count
    
    def _check_suspicious_patterns(self, clone_location: str) -> List[str]:
        """Check for suspicious patterns in repository"""
        
        warnings = []
        
        suspicious_files = [
            '.env',
            'credentials',
            'secrets',
            'private_key',
            'id_rsa',
            '.pem'
        ]
        
        for root, dirs, files in os.walk(clone_location):
            for file in files:
                # Check for suspicious filenames
                if any(suspicious in file.lower() for suspicious in suspicious_files):
                    warnings.append(f"Suspicious file found: {file}")
                
                # Check file size
                filepath = os.path.join(root, file)
                try:
                    size_mb = os.path.getsize(filepath) / (1024 * 1024)
                    if size_mb > 100:
                        warnings.append(f"Large file found: {file} ({size_mb:.1f}MB)")
                except:
                    pass
        
        return warnings
    
    def _parse_package_json(self, filepath: str) -> Dict[str, Any]:
        """Parse package.json for dependencies"""
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            dependencies = {}
            
            if 'dependencies' in data:
                dependencies['runtime'] = list(data['dependencies'].keys())
            
            if 'devDependencies' in data:
                dependencies['dev'] = list(data['devDependencies'].keys())
            
            return dependencies
            
        except Exception as e:
            logger.error(f"Failed to parse package.json: {e}")
            return {}
    
    def _parse_requirements_txt(self, filepath: str) -> List[str]:
        """Parse requirements.txt for dependencies"""
        
        dependencies = []
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract package name
                        pkg = line.split('==')[0].split('>=')[0].split('<=')[0]
                        dependencies.append(pkg)
            
            return dependencies
            
        except Exception as e:
            logger.error(f"Failed to parse requirements.txt: {e}")
            return []


def lambda_handler(event, context):
    """Lambda handler for repository cloning"""
    
    cloner = RepositoryCloner()
    
    try:
        # Handle batch cloning
        if 'repositories' in event:
            results = []
            for repo_config in event['repositories']:
                result = cloner.clone_repository(repo_config)
                results.append(result)
            
            return {
                'statusCode': 200,
                'cloned_count': len([r for r in results if r['statusCode'] == 200]),
                'results': results
            }
        else:
            # Single repository clone
            return cloner.clone_repository(event)
            
    except Exception as e:
        logger.error(f"Repository cloning failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }