"""
Sub-CEO Agent Logic - Priority-based file scanning and work distribution
"""
import os
import re
import json
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class FilePriority(Enum):
    """File priority levels for security scanning"""
    CRITICAL = 1  # Authentication, secrets, config files
    HIGH = 2      # API endpoints, database access, crypto
    MEDIUM = 3    # Business logic, data processing
    LOW = 4       # Tests, documentation, static assets


@dataclass
class FileGroup:
    """Represents a group of files for scanning"""
    group_id: str
    priority: FilePriority
    files: List[str] = field(default_factory=list)
    estimated_size_bytes: int = 0
    risk_indicators: List[str] = field(default_factory=list)
    
    def add_file(self, filepath: str, size_bytes: int = 0):
        """Add a file to the group"""
        self.files.append(filepath)
        self.estimated_size_bytes += size_bytes


class SubCEOAgent:
    """
    Sub-CEO Agent for intelligent file prioritization and work distribution
    """
    
    # Critical file patterns (highest priority)
    CRITICAL_PATTERNS = {
        'authentication': [
            r'.*auth.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*login.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*oauth.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*jwt.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*session.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
        ],
        'secrets_config': [
            r'.*\.(env|cfg|conf|config|ini|properties|yaml|yml|json)$',
            r'.*secret.*',
            r'.*credential.*',
            r'.*password.*',
            r'.*token.*',
            r'.*key.*\.(pem|key|p12|pfx|jks)$',
        ],
        'infrastructure': [
            r'Dockerfile.*',
            r'docker-compose.*\.ya?ml$',
            r'.*\.tf$',
            r'.*\.tfvars$',
            r'.*cloudformation.*\.(yaml|yml|json)$',
            r'.*k8s.*\.(yaml|yml)$',
            r'.*kubernetes.*\.(yaml|yml)$',
        ]
    }
    
    # High priority patterns
    HIGH_PATTERNS = {
        'api_endpoints': [
            r'.*(api|endpoint|route|controller).*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*(rest|graphql|grpc).*\.(py|js|java|go|rb|php|cs|cpp|c)$',
        ],
        'database': [
            r'.*db.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*database.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*sql.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*query.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*model.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
        ],
        'crypto': [
            r'.*crypt.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*hash.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*encrypt.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*decrypt.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
        ]
    }
    
    # Medium priority patterns
    MEDIUM_PATTERNS = {
        'business_logic': [
            r'.*service.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*handler.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*processor.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*manager.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
        ],
        'data_processing': [
            r'.*parser.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*serializer.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
            r'.*validator.*\.(py|js|java|go|rb|php|cs|cpp|c)$',
        ]
    }
    
    # Files to skip
    SKIP_PATTERNS = [
        r'\.git/.*',
        r'node_modules/.*',
        r'vendor/.*',
        r'\.idea/.*',
        r'\.vscode/.*',
        r'__pycache__/.*',
        r'.*\.(pyc|pyo|class|o|so|dll|exe)$',
        r'.*\.(jpg|jpeg|png|gif|ico|svg|webp)$',
        r'.*\.(mp3|mp4|avi|mov|wmv|flv)$',
        r'.*\.(zip|tar|gz|bz2|7z|rar)$',
        r'.*\.min\.(js|css)$',
    ]
    
    def __init__(self, repository_path: str, max_group_size_mb: int = 50):
        """
        Initialize Sub-CEO Agent
        
        Args:
            repository_path: Path to the cloned repository
            max_group_size_mb: Maximum size of a file group in MB
        """
        self.repository_path = repository_path
        self.max_group_size_bytes = max_group_size_mb * 1024 * 1024
        self.file_groups: Dict[str, FileGroup] = {}
        
    def analyze_and_group_files(self) -> Dict[str, Any]:
        """
        Analyze repository and create prioritized file groups
        
        Returns:
            Dictionary containing file groups and analysis metadata
        """
        logger.info(f"Sub-CEO analyzing repository: {self.repository_path}")
        
        # Scan all files in repository
        all_files = self._scan_repository()
        
        # Categorize files by priority
        prioritized_files = self._prioritize_files(all_files)
        
        # Create optimal file groups
        file_groups = self._create_file_groups(prioritized_files)
        
        # Generate work distribution plan
        work_plan = self._create_work_distribution_plan(file_groups)
        
        analysis_result = {
            'total_files': len(all_files),
            'total_groups': len(file_groups),
            'priority_distribution': self._get_priority_distribution(file_groups),
            'file_groups': [self._serialize_file_group(g) for g in file_groups],
            'work_plan': work_plan,
            'risk_summary': self._generate_risk_summary(file_groups)
        }
        
        logger.info(f"Sub-CEO analysis complete: {len(file_groups)} groups created")
        return analysis_result
    
    def _scan_repository(self) -> List[Tuple[str, int]]:
        """Scan repository and return list of (filepath, size) tuples"""
        files = []
        
        for root, _, filenames in os.walk(self.repository_path):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.repository_path)
                
                # Skip files matching skip patterns
                if any(re.match(pattern, relative_path) for pattern in self.SKIP_PATTERNS):
                    continue
                
                try:
                    size = os.path.getsize(filepath)
                    files.append((relative_path, size))
                except OSError:
                    logger.warning(f"Could not get size for file: {relative_path}")
                    files.append((relative_path, 0))
        
        return files
    
    def _prioritize_files(self, files: List[Tuple[str, int]]) -> Dict[FilePriority, List[Tuple[str, int, List[str]]]]:
        """
        Categorize files by priority level
        
        Returns:
            Dictionary mapping priority to list of (filepath, size, risk_indicators)
        """
        prioritized = {
            FilePriority.CRITICAL: [],
            FilePriority.HIGH: [],
            FilePriority.MEDIUM: [],
            FilePriority.LOW: []
        }
        
        for filepath, size in files:
            priority, risk_indicators = self._determine_file_priority(filepath)
            prioritized[priority].append((filepath, size, risk_indicators))
        
        return prioritized
    
    def _determine_file_priority(self, filepath: str) -> Tuple[FilePriority, List[str]]:
        """Determine priority level and risk indicators for a file"""
        risk_indicators = []
        
        # Check critical patterns
        for category, patterns in self.CRITICAL_PATTERNS.items():
            if any(re.match(pattern, filepath, re.IGNORECASE) for pattern in patterns):
                risk_indicators.append(f"critical:{category}")
                return FilePriority.CRITICAL, risk_indicators
        
        # Check high priority patterns
        for category, patterns in self.HIGH_PATTERNS.items():
            if any(re.match(pattern, filepath, re.IGNORECASE) for pattern in patterns):
                risk_indicators.append(f"high:{category}")
                return FilePriority.HIGH, risk_indicators
        
        # Check medium priority patterns
        for category, patterns in self.MEDIUM_PATTERNS.items():
            if any(re.match(pattern, filepath, re.IGNORECASE) for pattern in patterns):
                risk_indicators.append(f"medium:{category}")
                return FilePriority.MEDIUM, risk_indicators
        
        # Default to low priority
        return FilePriority.LOW, ["low:general"]
    
    def _create_file_groups(self, prioritized_files: Dict[FilePriority, List[Tuple[str, int, List[str]]]]) -> List[FileGroup]:
        """Create optimal file groups based on priority and size constraints"""
        groups = []
        group_counter = 0
        
        # Process files by priority (highest first)
        for priority in sorted(FilePriority, key=lambda p: p.value):
            files = prioritized_files[priority]
            
            if not files:
                continue
            
            # Sort files by size (largest first) for better bin packing
            files.sort(key=lambda x: x[1], reverse=True)
            
            current_group = FileGroup(
                group_id=f"group_{group_counter:03d}",
                priority=priority,
                risk_indicators=[]
            )
            
            for filepath, size, risk_indicators in files:
                # If adding this file would exceed max group size, start new group
                if current_group.files and current_group.estimated_size_bytes + size > self.max_group_size_bytes:
                    groups.append(current_group)
                    group_counter += 1
                    current_group = FileGroup(
                        group_id=f"group_{group_counter:03d}",
                        priority=priority,
                        risk_indicators=[]
                    )
                
                current_group.add_file(filepath, size)
                current_group.risk_indicators.extend(risk_indicators)
            
            # Add the last group if it has files
            if current_group.files:
                groups.append(current_group)
                group_counter += 1
        
        return groups
    
    def _create_work_distribution_plan(self, file_groups: List[FileGroup]) -> Dict[str, Any]:
        """Create an optimized work distribution plan for agents"""
        plan = {
            'parallel_groups': [],
            'execution_waves': [],
            'estimated_total_time': 0
        }
        
        # Group by priority for wave execution
        priority_groups = {}
        for group in file_groups:
            if group.priority not in priority_groups:
                priority_groups[group.priority] = []
            priority_groups[group.priority].append(group)
        
        # Create execution waves (critical files first)
        wave_number = 0
        for priority in sorted(FilePriority, key=lambda p: p.value):
            if priority not in priority_groups:
                continue
            
            groups = priority_groups[priority]
            
            # Split large waves into smaller parallel batches
            batch_size = 5  # Max groups to run in parallel
            for i in range(0, len(groups), batch_size):
                batch = groups[i:i + batch_size]
                wave = {
                    'wave_number': wave_number,
                    'priority': priority.name,
                    'groups': [g.group_id for g in batch],
                    'estimated_time_seconds': self._estimate_wave_time(batch)
                }
                plan['execution_waves'].append(wave)
                plan['estimated_total_time'] += wave['estimated_time_seconds']
                wave_number += 1
        
        # Identify groups that can run in parallel
        plan['parallel_groups'] = self._identify_parallel_groups(file_groups)
        
        return plan
    
    def _estimate_wave_time(self, groups: List[FileGroup]) -> int:
        """Estimate execution time for a wave of groups"""
        # Simple estimation: 1 second per MB + overhead
        max_size = max(g.estimated_size_bytes for g in groups) if groups else 0
        return int((max_size / (1024 * 1024)) + 30)  # 30 seconds overhead
    
    def _identify_parallel_groups(self, file_groups: List[FileGroup]) -> List[List[str]]:
        """Identify groups that can be safely run in parallel"""
        parallel_sets = []
        
        # Groups with same priority can run in parallel
        priority_groups = {}
        for group in file_groups:
            if group.priority not in priority_groups:
                priority_groups[group.priority] = []
            priority_groups[group.priority].append(group.group_id)
        
        for priority, group_ids in priority_groups.items():
            if len(group_ids) > 1:
                # Split into reasonable parallel sets (max 5 per set)
                for i in range(0, len(group_ids), 5):
                    parallel_sets.append(group_ids[i:i+5])
        
        return parallel_sets
    
    def _serialize_file_group(self, group: FileGroup) -> Dict[str, Any]:
        """Serialize FileGroup to dictionary"""
        return {
            'group_id': group.group_id,
            'priority': group.priority.name,
            'priority_value': group.priority.value,
            'file_count': len(group.files),
            'files': group.files[:10],  # First 10 files as sample
            'total_size_mb': round(group.estimated_size_bytes / (1024 * 1024), 2),
            'risk_indicators': list(set(group.risk_indicators))[:5]  # Top 5 unique indicators
        }
    
    def _get_priority_distribution(self, file_groups: List[FileGroup]) -> Dict[str, int]:
        """Get distribution of files by priority"""
        distribution = {p.name: 0 for p in FilePriority}
        
        for group in file_groups:
            distribution[group.priority.name] += len(group.files)
        
        return distribution
    
    def _generate_risk_summary(self, file_groups: List[FileGroup]) -> Dict[str, Any]:
        """Generate a risk summary based on file analysis"""
        risk_categories = {}
        high_risk_files = []
        
        for group in file_groups:
            if group.priority in [FilePriority.CRITICAL, FilePriority.HIGH]:
                high_risk_files.extend(group.files[:5])  # Top 5 from each group
            
            for indicator in group.risk_indicators:
                category = indicator.split(':')[1] if ':' in indicator else 'unknown'
                risk_categories[category] = risk_categories.get(category, 0) + 1
        
        return {
            'high_risk_file_count': len(high_risk_files),
            'risk_categories': risk_categories,
            'sample_high_risk_files': high_risk_files[:10]
        }
    
    def get_files_for_agent(self, agent_type: str, group_id: str) -> List[str]:
        """
        Get list of files for a specific agent and group
        
        Args:
            agent_type: Type of security agent
            group_id: File group ID
            
        Returns:
            List of file paths to scan
        """
        if group_id not in self.file_groups:
            logger.warning(f"Group {group_id} not found")
            return []
        
        group = self.file_groups[group_id]
        
        # Filter files based on agent type if needed
        # For now, return all files in the group
        return group.files