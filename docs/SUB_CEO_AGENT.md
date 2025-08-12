# Sub-CEO Agent - Priority-Based File Scanning

## Overview

The Sub-CEO Agent is a sophisticated component of the HASHIRU framework that implements intelligent file prioritization and work distribution for security scanning. It analyzes repository structure and creates optimized file groups based on security risk levels, enabling more efficient and targeted scanning.

## Key Features

### 1. **File Prioritization**
- **CRITICAL**: Authentication files, secrets, configuration files, infrastructure definitions
- **HIGH**: API endpoints, database access, cryptographic operations
- **MEDIUM**: Business logic, data processing
- **LOW**: Tests, documentation, static assets

### 2. **Smart File Grouping**
- Groups files by priority and size constraints (default 50MB per group)
- Optimizes for parallel execution while respecting dependencies
- Uses bin packing algorithm for efficient resource utilization

### 3. **Risk-Based Analysis**
- Identifies high-risk file patterns automatically
- Provides risk indicators for each file group
- Prioritizes critical security-sensitive files first

## Architecture

```
┌─────────────────┐
│   CEO Agent     │
│                 │
│ ┌─────────────┐ │
│ │  Sub-CEO    │ │
│ │   Agent     │ │
│ └─────────────┘ │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ File Analysis   │
│ - Scan repo     │
│ - Prioritize    │
│ - Group files   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Work Plan       │
│ - Parallel exec │
│ - Wave planning │
│ - Cost optimize │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Security Agents │
│ - SAST          │
│ - Secrets       │
│ - Dependencies  │
└─────────────────┘
```

## Integration with HASHIRU

The Sub-CEO agent is integrated into the HASHIRU ExecutionPlanner:

```python
# In ExecutionPlanner.__init__
self.sub_ceo_agent = SubCEOAgent(repo_path) if repo_path else None

# During planning
if self.sub_ceo_agent:
    file_analysis = self.sub_ceo_agent.analyze_and_group_files()
```

## File Group Structure

Each file group contains:
- `group_id`: Unique identifier (e.g., "group_001")
- `priority`: Priority level (CRITICAL, HIGH, MEDIUM, LOW)
- `files`: List of file paths in the group
- `estimated_size_bytes`: Total size of files in the group
- `risk_indicators`: List of security risk indicators

## Agent Integration

Security agents (SAST, Secrets) now support file group-based scanning:

### SAST Agent
```python
# Checks for file group in Strands message
if 'file_group' in custom_config:
    # Scans only files in the specified group
    # Uses --target-file option with Semgrep
```

### Secrets Agent
```python
# Creates temporary directory with symlinks
# Scans only files in the specified group
# Maintains file structure for accurate reporting
```

## Work Distribution Plan

The Sub-CEO creates an optimized work distribution plan:

1. **Execution Waves**: Groups organized by priority
2. **Parallel Groups**: Identifies groups that can run simultaneously
3. **Time Estimation**: Estimates execution time per wave
4. **Resource Optimization**: Balances load across available resources

## Configuration

The Sub-CEO agent can be configured with:
- `max_group_size_mb`: Maximum size of each file group (default: 50MB)
- Custom file patterns for each priority level
- Exclusion patterns for files to skip

## Benefits

1. **Faster Critical Issue Detection**: High-risk files scanned first
2. **Improved Resource Utilization**: Parallel execution of independent groups
3. **Better Cost Control**: Optimized scanning reduces execution time
4. **Scalability**: Handles large repositories efficiently
5. **Flexibility**: Adapts to different repository structures

## Example Output

```json
{
  "total_files": 1523,
  "total_groups": 12,
  "priority_distribution": {
    "CRITICAL": 234,
    "HIGH": 456,
    "MEDIUM": 678,
    "LOW": 155
  },
  "file_groups": [
    {
      "group_id": "group_001",
      "priority": "CRITICAL",
      "file_count": 45,
      "total_size_mb": 12.5,
      "risk_indicators": ["critical:authentication", "critical:secrets_config"]
    }
  ],
  "work_plan": {
    "execution_waves": [
      {
        "wave_number": 0,
        "priority": "CRITICAL",
        "groups": ["group_001", "group_002"],
        "estimated_time_seconds": 120
      }
    ],
    "estimated_total_time": 480
  }
}
```

## Future Enhancements

1. **Machine Learning Integration**: Learn from past scans to improve prioritization
2. **Dynamic Re-prioritization**: Adjust priorities based on findings in real-time
3. **Cross-Repository Learning**: Apply patterns learned from one repo to others
4. **Custom Priority Rules**: Allow users to define custom prioritization logic