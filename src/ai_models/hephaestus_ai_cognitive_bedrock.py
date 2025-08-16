"""
Hephaestus AI Cognitive + Bedrock: Hybrid Vulnerability Discovery System
=======================================================================
Combines the cognitive flow innovation framework with AWS Bedrock's analysis capabilities
for advanced vulnerability chain discovery with detailed function-level information.
"""

import os
import json
import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from pathlib import Path
from datetime import datetime
from enum import Enum
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class InnovationPhase(Enum):
    """Phases in the bug discovery innovation workflow"""
    EXPLORATION = "exploration"      # Explore code structure and patterns
    HYPOTHESIS = "hypothesis"        # Generate bug hypotheses using AI
    EXPERIMENTATION = "experimentation"  # Test hypotheses with targeted analysis
    VALIDATION = "validation"        # Validate findings with POCs
    LEARNING = "learning"           # Learn from results and adapt
    EVOLUTION = "evolution"         # Evolve strategies based on findings


@dataclass
class VulnerabilityChain:
    """Enhanced vulnerability chain with cognitive context"""
    id: str
    title: str
    description: str
    severity: str
    confidence: float
    steps: List[Dict[str, Any]]
    impact: str
    exploit_scenario: str
    mitigations: List[str]
    code_locations: List[Dict[str, Any]]
    # Enhanced fields
    attack_path: List[Dict[str, str]] = field(default_factory=list)
    functions_involved: List[Dict[str, Any]] = field(default_factory=list)
    entry_points: List[Dict[str, str]] = field(default_factory=list)
    exploitation_techniques: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    post_exploitation: List[str] = field(default_factory=list)
    # Reachability analysis
    reachability: Dict[str, Any] = field(default_factory=dict)
    # Cognitive fields
    innovation_phase: str = ""
    discovery_iteration: int = 0
    hypothesis_source: str = ""  # pattern, ai, evolution, learning
    poc_code: str = ""


class CognitiveBedrockAnalyzer:
    """Hybrid analyzer combining cognitive flow with AWS Bedrock"""
    
    def __init__(self, region_name: Optional[str] = None, model_id: Optional[str] = None):
        self.region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.model_id = model_id or os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
        
        # Validate model ID format
        if not self.model_id.startswith(('anthropic.claude', 'meta.llama', 'amazon.titan')):
            logger.warning(f"Unusual model ID format: {self.model_id}. Ensure it's a valid Bedrock model.")
        
        # Initialize Bedrock client
        try:
            self.bedrock_runtime = boto3.client(
                service_name='bedrock-runtime',
                region_name=self.region_name
            )
            # Test the client connection
            logger.info(f"✅ Bedrock client initialized in region: {self.region_name}")
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            logger.error("Ensure AWS credentials are configured and you have access to Bedrock")
            raise
        
        self.current_phase = InnovationPhase.EXPLORATION
        self.learning_memory = defaultdict(list)  # Store successful patterns
        self.hypothesis_history = []
        self.iteration_count = 0
        self.loaded_files = []  # Pre-loaded file contents
        self.discovered_chains_cache = []  # Cache for discovered chains
        
    async def analyze_with_cognitive_flow(self, repo_path: str, max_iterations: int = 3) -> List[VulnerabilityChain]:
        """Analyze repository using cognitive flow with AI enhancement
        
        Each iteration = 1 complete cycle through all 6 phases
        """
        logger.info(f"🧠 Starting Cognitive + Bedrock analysis of {repo_path}")
        logger.info(f"📍 Each iteration = 1 complete cycle through all 6 phases")
        
        # Pre-load all files into memory once
        logger.info("📂 Loading all files into memory...")
        self._load_files(repo_path)
        logger.info(f"✅ Loaded {len(self.loaded_files)} files")
        
        all_chains = []
        discovered_chain_ids = set()
        critical_chains = []  # Track critical vulnerabilities
        phase_effectiveness = defaultdict(int)  # Track which phases find bugs
        
        # Modified phase order - start aggressive
        phase_order = [
            InnovationPhase.EXPLORATION,      # Find initial bugs
            InnovationPhase.EXPERIMENTATION,  # Break things immediately
            InnovationPhase.HYPOTHESIS,       # Generate attack chains
            InnovationPhase.VALIDATION,       # Validate critical findings
            InnovationPhase.LEARNING,         # Learn patterns
            InnovationPhase.EVOLUTION         # Find advanced bugs
        ]
        
        for iteration in range(max_iterations):
            self.iteration_count = iteration + 1
            logger.info(f"\n{'='*70}")
            logger.info(f"🔄 ITERATION {iteration + 1}/{max_iterations} - Adaptive Cognitive Cycle")
            logger.info(f"{'='*70}\n")
            
            iteration_new_chains = 0
            iteration_critical_chains = 0
            
            # Adaptive phase execution based on effectiveness
            if iteration > 0:
                # Prioritize phases that found critical bugs
                phase_order = sorted(phase_order,
                                   key=lambda p: phase_effectiveness.get(p.value, 0),
                                   reverse=True)
            
            for phase_index, phase in enumerate(phase_order):
                self.current_phase = phase
                logger.info(f"\n{'─'*50}")
                logger.info(f"🎯 Phase {phase_index + 1}/6: {phase.value.upper()}")
                logger.info(f"   Previous effectiveness: {phase_effectiveness.get(phase.value, 0)} critical bugs")
                logger.info(f"{'─'*50}")
                
                # Execute current phase
                phase_chains = await self._execute_phase(repo_path, discovered_chain_ids)
                
                # Process new chains with priority on critical ones
                phase_new_chains = 0
                phase_critical = 0
                
                for chain in phase_chains:
                    if chain.id not in discovered_chain_ids:
                        discovered_chain_ids.add(chain.id)
                        chain.innovation_phase = phase.value
                        chain.discovery_iteration = iteration + 1
                        all_chains.append(chain)
                        phase_new_chains += 1
                        iteration_new_chains += 1
                        
                        # Track critical vulnerabilities
                        if chain.severity in ["critical", "high"]:
                            critical_chains.append(chain)
                            phase_critical += 1
                            iteration_critical_chains += 1
                            phase_effectiveness[phase.value] += 1
                            
                            # IMMEDIATE RE-EXPLORATION for critical bugs
                            logger.info(f"🚨 CRITICAL BUG FOUND: {chain.title}")
                            logger.info(f"   Triggering targeted re-exploration...")
                            
                            # Learn and immediately look for similar patterns
                            self._learn_from_chain(chain)
                            
                            # Quick targeted exploration for similar bugs
                            if phase != InnovationPhase.EXPLORATION:
                                similar_chains = await self._targeted_exploration(
                                    repo_path, chain, discovered_chain_ids
                                )
                                for similar in similar_chains:
                                    if similar.id not in discovered_chain_ids:
                                        discovered_chain_ids.add(similar.id)
                                        similar.innovation_phase = "targeted_exploration"
                                        similar.discovery_iteration = iteration + 1
                                        all_chains.append(similar)
                                        critical_chains.append(similar)
                                        logger.info(f"   🎯 Found similar: {similar.title}")
                        else:
                            # Still learn from non-critical discoveries
                            self._learn_from_chain(chain)
                
                logger.info(f"✅ {phase.value} found {phase_new_chains} new chains ({phase_critical} critical)")
                
                # Skip remaining phases if we found many critical bugs
                if phase_critical >= 3:
                    logger.info(f"🔥 Found {phase_critical} critical bugs - focusing on exploitation")
                    # Jump directly to validation/exploitation
                    if phase != InnovationPhase.VALIDATION:
                        self.current_phase = InnovationPhase.VALIDATION
                        validation_chains = await self._execute_phase(repo_path, discovered_chain_ids)
                        for chain in validation_chains:
                            if chain.id not in discovered_chain_ids and chain.severity in ["critical", "high"]:
                                discovered_chain_ids.add(chain.id)
                                all_chains.append(chain)
                                critical_chains.append(chain)
                    break
            
            # Summary for this iteration
            logger.info(f"\n🎯 Iteration {iteration + 1} Complete:")
            logger.info(f"   • Total new chains: {iteration_new_chains}")
            logger.info(f"   • Critical/High severity: {iteration_critical_chains}")
            logger.info(f"   • Cumulative total: {len(all_chains)}")
            logger.info(f"   • Total critical: {len(critical_chains)}")
            
            # Modified convergence - continue if finding critical bugs
            if iteration_new_chains == 0:
                logger.info("🏁 Convergence reached - no new chains found")
                break
            elif iteration_critical_chains == 0 and iteration > 1:
                logger.info("⚠️  No critical bugs in this iteration - one more try")
                # Give it one more aggressive iteration
                self.current_phase = InnovationPhase.EVOLUTION
                evolution_chains = await self._execute_phase(repo_path, discovered_chain_ids)
                for chain in evolution_chains:
                    if chain.id not in discovered_chain_ids and chain.severity in ["critical", "high"]:
                        all_chains.append(chain)
                        critical_chains.append(chain)
                break
        
        # Generate POCs for high-confidence chains
        logger.info(f"\n🔧 Generating POCs for high-confidence chains...")
        await self._generate_pocs_for_chains(all_chains)
        
        # Update cache for future phases
        self.discovered_chains_cache = all_chains
        
        return all_chains
    
    async def _execute_phase(self, repo_path: str, discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Execute the current innovation phase"""
        
        if self.current_phase == InnovationPhase.EXPLORATION:
            return await self._exploration_phase(repo_path)
        elif self.current_phase == InnovationPhase.HYPOTHESIS:
            return await self._hypothesis_phase(repo_path, discovered_ids)
        elif self.current_phase == InnovationPhase.EXPERIMENTATION:
            return await self._experimentation_phase(repo_path, discovered_ids)
        elif self.current_phase == InnovationPhase.VALIDATION:
            return await self._validation_phase(repo_path, discovered_ids)
        elif self.current_phase == InnovationPhase.LEARNING:
            return await self._learning_phase(repo_path, discovered_ids)
        elif self.current_phase == InnovationPhase.EVOLUTION:
            return await self._evolution_phase(repo_path, discovered_ids)
        
        return []
    
    async def _exploration_phase(self, repo_path: str) -> List[VulnerabilityChain]:
        """Exploration: Initial broad analysis to understand the codebase"""
        logger.info("🔍 EXPLORATION: Discovering attack surface and patterns")
        
        prompt = """You are an elite vulnerability researcher analyzing a SECURITY-CRITICAL CODEBASE.

FIND ALL BUGS - including RUNTIME and DEPLOYMENT vulnerabilities!

COMPREHENSIVE BUG CATEGORIES TO HUNT:

**RUNTIME SECURITY VULNERABILITIES** (CRITICAL):
1. **File System Attacks**:
   - Writable installation directories
   - Shared temp file vulnerabilities
   - Config file injection/replacement
   - Plugin/extension directory attacks
   - Log file poisoning
   
2. **Dynamic Loading Exploits**:
   - DLL/SO hijacking
   - Library search order issues
   - Plugin loading vulnerabilities
   - Module injection attacks
   - Interpreter/runtime manipulation

3. **Environment Variable Attacks**:
   - PATH manipulation
   - LD_*/DYLD_* library paths
   - Proxy settings injection
   - Debug flag activation
   - Feature toggle manipulation

4. **Permission & Access Issues**:
   - Weak file/directory permissions
   - Insecure default configurations
   - Privilege dropping failures
   - TOCTOU in permission checks
   - Symlink/hardlink attacks

**DEPLOYMENT VULNERABILITIES**:
5. **Installation/Update Flaws**:
   - Insecure update mechanisms
   - Unsigned package verification
   - MITM during downloads
   - Rollback attacks
   - Partial update failures

6. **Inter-Process Attacks**:
   - IPC injection
   - Shared memory corruption
   - Signal handler abuse
   - Named pipe hijacking
   - Socket takeover

**STATIC SECURITY VULNERABILITIES**:
7. Memory Corruption: buffer overflows, use-after-free
8. Injection: command/SQL injection, path traversal
9. Authentication/Authorization: bypasses, privilege escalation
10. Information Disclosure: data leaks, timing attacks

**FUNCTIONAL BUGS**:
5. **Logic Errors**: incorrect algorithms, wrong calculations, off-by-one
6. **State Bugs**: invalid state transitions, inconsistent state
7. **API Violations**: contract breaches, invariant violations
8. **Data Corruption**: incorrect data handling, precision loss

**PERFORMANCE BUGS**:
9. **Memory Leaks**: forgotten frees, circular references
10. **Resource Leaks**: file descriptors, sockets, handles
11. **Inefficiency**: O(n²) when O(n) possible, unnecessary work
12. **CPU Spins**: busy waiting, infinite loops

**CONCURRENCY BUGS**:
13. **Deadlocks**: circular lock dependencies, lock ordering
14. **Race Conditions**: data races, TOCTOU, missing synchronization
15. **Livelocks**: threads spinning without progress
16. **Atomicity Violations**: non-atomic operations on shared data

**ERROR HANDLING BUGS**:
17. **Unhandled Errors**: ignored return codes, missing try/catch
18. **Error Path Bugs**: cleanup failures, resource leaks on error
19. **Cascading Failures**: error propagation issues
20. **Recovery Bugs**: incorrect error recovery logic

**COMPATIBILITY BUGS**:
21. **API Breaking Changes**: incompatible updates
22. **Platform Issues**: OS-specific bugs, endianness
23. **Version Mismatches**: dependency conflicts
24. **Protocol Violations**: spec non-compliance

**USABILITY BUGS**:
25. **Confusing Behavior**: unexpected results, poor UX
26. **Bad Error Messages**: unclear, missing context
27. **Documentation Mismatches**: code doesn't match docs
28. **Configuration Issues**: bad defaults, unclear options

DEEP ANALYSIS REQUIREMENTS:
- **Correctness**: Does the code do what it claims to do?
- **Edge Cases**: Empty inputs, maximum values, boundary conditions
- **Error Paths**: What happens when things go wrong?
- **Resource Management**: Are all resources properly cleaned up?
- **Concurrency**: Thread safety, race conditions, deadlocks
- **Performance**: Algorithmic complexity, unnecessary allocations
- **Maintainability**: Code smells, technical debt, complexity
- **Standards Compliance**: Does it follow specs/RFCs/protocols?

BUG IMPACT ASSESSMENT:
- **Critical**: Security exploits, data loss, system crashes
- **High**: Functional failures, severe performance issues
- **Medium**: Minor functional bugs, moderate performance impact
- **Low**: Cosmetic issues, minor inefficiencies

ANALYSIS APPROACH:
- **Static Analysis**: Check code for traditional bugs
- **Runtime Analysis**: How is this deployed? What's mounted?
- **Configuration Review**: What permissions/capabilities needed?
- **Attack Surface Mapping**: What's exposed at runtime?
- **Deployment Scenarios**: How could this be misconfigured?
- **Container Security**: Escape paths, namespace issues

RUNTIME VULNERABILITY EXAMPLES TO FIND:
- "If install directory is world-writable, attacker can replace binaries"
- "If app loads plugins from user-writable directory, code execution"
- "If config file permissions allow modification, security bypass"
- "If PATH is user-controlled, command injection via system calls"
- "If temp files are predictable, symlink attacks possible"
- "If update server isn't verified, malicious updates can be installed"

CRITICAL RUNTIME CHECKS:
1. What directories/files can users write to?
2. How are external libraries/plugins loaded?
3. What environment variables are trusted?
4. How are updates/patches delivered?
5. What happens if attacker controls config files?
6. Are there race conditions in file operations?
7. How does the app handle symlinks/hardlinks?
8. What IPC mechanisms are used?

REPORT ALL VULNERABILITIES - static AND runtime!
Focus especially on deployment/configuration issues that enable attacks!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "exploration")
    
    async def _hypothesis_phase(self, repo_path: str, discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Hypothesis: Generate targeted vulnerability CHAINS based on exploration"""
        logger.info("💡 HYPOTHESIS: Generating vulnerability CHAINS and attack paths")
        
        # Build a list of discovered chains from the hypothesis history
        # Note: In a real implementation, we'd pass discovered_chains as a parameter
        discovered_chains = []
        if hasattr(self, 'discovered_chains_cache'):
            discovered_chains = self.discovered_chains_cache
        
        # Extract key vulnerability primitives
        primitives = self._extract_vulnerability_primitives(discovered_chains)
        
        # Build context with discovered bugs
        context = f"""
DISCOVERED VULNERABILITY PRIMITIVES:
{json.dumps(primitives, indent=2)}

PREVIOUS CHAINS: {len(discovered_chains)}
HIGH/CRITICAL: {len([c for c in discovered_chains if c.severity in ['high', 'critical']])}
"""
        
        prompt = f"""You are in the HYPOTHESIS phase - CREATE VULNERABILITY CHAINS!

{context}

YOUR MISSION: Generate attack chains INCLUDING RUNTIME vulnerabilities!

CHAIN GENERATION STRATEGIES:

1. **Binary Replacement Chain**:
   - Identify writable install directory
   - Replace application binary
   - Wait for restart/execution
   - Example: /opt/app is 777 → Replace app.exe → Code execution

2. **Plugin/Extension Attack Chain**:
   - Find plugin directory
   - Drop malicious plugin
   - App loads on startup
   - Example: ~/.app/plugins → Drop evil.so → RCE on load

3. **Library Hijacking Chain**:
   - Identify library search path
   - Place malicious library first
   - App loads attacker's version
   - Example: ./lib before /usr/lib → Drop libc.so → Full control

4. **Config File Attack Chain**:
   - Find writable config
   - Inject malicious settings
   - App trusts and executes
   - Example: app.conf → Add exec_cmd=/bin/sh → Command execution

5. **Update Hijacking Chain**:
   - MITM update check
   - Serve malicious update
   - App installs backdoor
   - Example: HTTP updates → DNS hijack → Malicious patch → Persistent access

6. **Environment Variable Chain**:
   - Control user environment
   - Set malicious paths/flags
   - App uses without validation
   - Example: PATH=./evil:$PATH → App calls 'ls' → Runs ./evil/ls

7. **IPC Hijacking Chain**:
   - Find IPC mechanism (pipes, sockets)
   - Inject commands/data
   - App processes as trusted
   - Example: Named pipe → Send admin commands → Privilege escalation

8. **Temp File Race Chain**:
   - Predict temp file names
   - Create symlink to target
   - App writes through symlink
   - Example: /tmp/app.XXXXX → Symlink to /etc/passwd → Overwrite

CHAIN CONSTRUCTION RULES:
- Each chain needs 2-5 steps
- Each step must be technically feasible
- Show how output of step N enables step N+1
- Focus on CRITICAL impact (RCE, sandbox escape, root)
- Consider real-world constraints

GENERATE AT LEAST 5 CONCRETE CHAINS:
For each chain provide:
- Chain name
- Step-by-step exploitation
- Required primitives from discovered bugs
- Success probability
- Impact severity

BE CREATIVE BUT REALISTIC:
- Think like a professional exploit developer
- Consider partial chains that need one more bug
- Identify "almost complete" kill chains
- Note what's missing to complete the chain

Previous hypotheses: {[h['title'] for h in self.hypothesis_history]}
BUILD MORE COMPLEX CHAINS!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "hypothesis")
    
    def _extract_vulnerability_primitives(self, chains: List[VulnerabilityChain]) -> Dict[str, List[str]]:
        """Extract reusable vulnerability primitives from discovered chains"""
        primitives = {
            "info_leaks": [],
            "memory_corruption": [],
            "logic_bugs": [],
            "race_conditions": [],
            "privilege_escalation": [],
            "input_validation": [],
            "integer_issues": [],
            "authentication": []
        }
        
        for chain in chains:
            # Categorize by exploitation techniques
            for technique in chain.exploitation_techniques:
                technique_lower = technique.lower()
                if "leak" in technique_lower or "disclosure" in technique_lower:
                    primitives["info_leaks"].append(f"{chain.title} - {technique}")
                elif "overflow" in technique_lower or "corruption" in technique_lower:
                    primitives["memory_corruption"].append(f"{chain.title} - {technique}")
                elif "race" in technique_lower or "toctou" in technique_lower:
                    primitives["race_conditions"].append(f"{chain.title} - {technique}")
                elif "privilege" in technique_lower or "escalation" in technique_lower:
                    primitives["privilege_escalation"].append(f"{chain.title} - {technique}")
                elif "integer" in technique_lower:
                    primitives["integer_issues"].append(f"{chain.title} - {technique}")
                elif "auth" in technique_lower:
                    primitives["authentication"].append(f"{chain.title} - {technique}")
                elif "logic" in technique_lower:
                    primitives["logic_bugs"].append(f"{chain.title} - {technique}")
                else:
                    primitives["input_validation"].append(f"{chain.title} - {technique}")
            
            # Also categorize by vulnerability type in functions
            for func in chain.functions_involved:
                vuln = func.get("vulnerability", "").lower()
                if "leak" in vuln:
                    primitives["info_leaks"].append(f"{func.get('name')} - {vuln}")
                elif "overflow" in vuln or "corruption" in vuln:
                    primitives["memory_corruption"].append(f"{func.get('name')} - {vuln}")
                # ... etc
        
        # Remove duplicates and empty categories
        return {k: list(set(v)) for k, v in primitives.items() if v}
    
    async def _experimentation_phase(self, repo_path: str, discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Experimentation: Test specific vulnerability CHAINS with targeted analysis"""
        logger.info("🧪 EXPERIMENTATION: Testing vulnerability CHAINS and hypotheses")
        
        # Get recent hypotheses including chains
        recent_hypotheses = self.hypothesis_history[-10:] if self.hypothesis_history else []
        
        # Get vulnerability chains from hypothesis phase
        chain_context = ""
        if hasattr(self, 'discovered_chains_cache'):
            hypothesis_chains = [c for c in self.discovered_chains_cache
                               if c.innovation_phase == "hypothesis" and c.severity in ["critical", "high"]]
            if hypothesis_chains:
                chain_context = f"""
VULNERABILITY CHAINS TO TEST:
{json.dumps([{
    'title': c.title,
    'steps': c.steps,
    'impact': c.impact
} for c in hypothesis_chains[:5]], indent=2)}
"""
        
        prompt = f"""You are in the EXPERIMENTATION phase - TEST THE CHAINS!

Recent chain hypotheses:
{json.dumps(recent_hypotheses, indent=2)}

{chain_context}

CHAIN EXPERIMENTATION OBJECTIVES:

1. **Validate Each Chain Step**:
   - Can step 1 actually be triggered?
   - Does output of step 1 enable step 2?
   - Can we complete the full chain?
   - What are the success rates?

2. **Test Chain Combinations**:
   - Info leak chain: Can we leak ASLR? Stack canaries? Heap metadata?
   - Memory corruption chain: Can we control RIP? Corrupt heap? Overflow stack?
   - Privilege escalation chain: Can we actually get root? Escape sandbox?
   - Container escape chain: Can we reach host? Break namespaces?

3. **Chain Reliability Testing**:
   - Does the chain work consistently?
   - What are failure points?
   - Can we make it more reliable?
   - Alternative paths if one step fails?

4. **Exploit Primitive Testing**:
   - Test each primitive in isolation
   - Combine primitives in new ways
   - Find missing primitives for incomplete chains
   - Discover new primitives

5. **Environmental Testing**:
   - Does chain work in default config?
   - Different OS versions?
   - With security features enabled?
   - In production-like environments?

6. **Advanced Chain Techniques**:
   - Race condition chains: Win multiple races in sequence
   - Side-channel chains: Leak → Exploit → Persist
   - Supply chain attacks: Inject → Spread → Control
   - Physics-based chains: Rowhammer → Kernel exploit

EXPERIMENTAL REQUIREMENTS:
- Test ACTUAL CODE PATHS - no speculation
- Document EXACT steps to reproduce
- Note success/failure rates
- Identify missing links in chains
- Find alternative chain paths

PRIORITIZE:
1. Container escape chains (critical for gVisor)
2. Privilege escalation chains
3. Remote code execution chains
4. Sandbox bypass chains

BE METHODICAL:
- Test each chain step-by-step
- Note what works and what doesn't
- Find the missing pieces
- Make chains more reliable

Document EVERYTHING - we're building exploit chains here!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "experimentation")
    
    async def _validation_phase(self, repo_path: str, discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Validation: Validate findings and create proof-of-concepts"""
        logger.info("✓ VALIDATION: Validating discoveries with deeper analysis")
        
        prompt = """You are in the VALIDATION phase - CONFIRM THE KILLS including RUNTIME attacks!

VALIDATE ALL VULNERABILITIES INCLUDING RUNTIME:

1. **Runtime Attack Validation**:
   - Volume mount attacks: Can we actually overwrite binaries?
   - Library injection: Does LD_PRELOAD/LD_LIBRARY_PATH work?
   - Config manipulation: Can we modify security policies?
   - Container escape: Can we break out via mounts?
   - Permission abuse: Do world-writable dirs exist?

2. **Deployment Scenario Testing**:
   - Docker/Kubernetes: How is this typically deployed?
   - Volume mounts: What's commonly mounted?
   - Capabilities: What's usually granted?
   - Network exposure: What ports/services exposed?
   - Multi-container: Shared volumes/namespaces?

3. **Static Vulnerability Validation**:
   - Memory corruption: Can we control RIP?
   - Logic bugs: Do they actually trigger?
   - Race conditions: Are they exploitable?
   - Info leaks: What can we actually leak?

4. **Attack Chain Validation**:
   - Runtime chains: Mount → Write → Execute
   - Hybrid chains: Static bug + runtime config
   - Persistence: Can we maintain access?
   - Lateral movement: Container to container?

5. **Real Deployment Tests**:
   - Default Docker run commands
   - Common Kubernetes manifests
   - Popular deployment tools
   - CI/CD pipeline configs

RUNTIME EXPLOIT EXAMPLES TO VALIDATE:
```
# Binary replacement
chmod 777 /opt/app && echo "malicious" > /opt/app/binary
# → Next execution runs attacker code

# Plugin injection
cp malicious.so ~/.app/plugins/
# → App loads attacker plugin on startup

# Library hijacking
export LD_LIBRARY_PATH=/tmp/evil:$LD_LIBRARY_PATH
# → App loads attacker's libraries

# Config manipulation
echo "exec_cmd = /bin/sh" >> /etc/app.conf
# → App executes shell commands

# Environment attacks
export PATH=/tmp/evil:$PATH
# → App runs attacker's binaries
```

VALIDATION CRITERIA:
- Works in REAL deployment scenarios
- Exploitable with common configurations
- Not just theoretical - actually works
- Clear steps to reproduce
- Impact on production systems

REPORT BOTH:
- Static code vulnerabilities
- Runtime/deployment vulnerabilities
- Configuration weaknesses
- Supply chain risks

This is where we validate REAL WORLD ATTACKS!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "validation")
    
    async def _learning_phase(self, repo_path: str, discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Learning: Learn from discoveries to find similar patterns"""
        logger.info("📚 LEARNING: Applying learned patterns to find variants")
        
        # Get successful patterns from memory
        learned_patterns = self._get_learned_patterns()
        
        prompt = f"""You are in the LEARNING phase - WEAPONIZE THE KNOWLEDGE!

Successful attack patterns: {json.dumps(learned_patterns, indent=2)}

EXPAND AND WEAPONIZE WHAT WORKED:

1. **Pattern Amplification**:
   - Where else do these bug patterns exist?
   - Can we automate finding similar vulnerabilities?
   - Are there systematic architectural flaws?
   - Do these bugs have variants/siblings?

2. **Attack Surface Expansion**:
   - Found one RCE? Find ALL the RCEs
   - Found one privesc? Check ALL privilege boundaries
   - Found one leak? Dump ALL the memory
   - Found one race? Race ALL the things

3. **Exploit Technique Evolution**:
   - Can we make exploits more reliable?
   - Ways to bypass newer mitigations?
   - Chaining for greater impact?
   - Making exploits architecture-independent?

4. **Systematic Weaknesses**:
   - Design flaws vs implementation bugs?
   - Repeated anti-patterns in the code?
   - Missing security controls?
   - Architectural vulnerabilities?

5. **0-Day Potential**:
   - Which bugs are most likely undiscovered?
   - Novel attack vectors others missed?
   - Bugs hiding in plain sight?
   - Supply chain attack opportunities?

LEARNING GOALS:
- Turn one bug into a bug class
- Convert local bugs to remote exploits
- Chain minor issues into critical compromises
- Find the bugs that scanners miss

The best hackers learn and adapt - BE ONE!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "learning")
    
    async def _evolution_phase(self, repo_path: str, discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Evolution: Evolve strategies to find completely new bug classes"""
        logger.info("🧬 EVOLUTION: Evolving strategies for novel discoveries")
        
        prompt = """You are in the EVOLUTION phase - TRANSCEND CONVENTIONAL HACKING!
EVOLVE TO FIND ALL TYPES OF MODERN BUGS:

**NEXT-GEN SECURITY BUGS**:
1. **Hardware-Software Boundary**: Spectre variants, Rowhammer, fault injection
2. **Supply Chain**: Dependency confusion, build injection, compiler bugs
3. **AI/ML Vulnerabilities**: Model poisoning, adversarial inputs
4. **Quantum Computing**: Post-quantum crypto weaknesses

**MODERN FUNCTIONAL BUGS**:
5. **Distributed System Bugs**:
   - Consensus failures
   - Split-brain scenarios
   - CAP theorem violations
   - Eventual consistency issues

6. **Cloud-Native Bugs**:
   - Container orchestration failures
   - Service mesh issues
   - Serverless cold start problems
   - Multi-tenancy isolation failures

7. **Microservice Bugs**:
   - Service discovery failures
   - Circuit breaker issues
   - Distributed tracing gaps
   - API versioning conflicts

**PERFORMANCE & SCALABILITY**:
8. **Modern Performance Issues**:
   - Cache invalidation storms
   - Thundering herd problems
   - Tail latency spikes
   - Memory bloat in long-running services

9. **Resource Optimization**:
   - Inefficient container packing
   - Wasted cloud resources
   - Suboptimal query plans
   - Unnecessary network calls

**DEVELOPER EXPERIENCE BUGS**:
10. **API Design Issues**:
    - Confusing interfaces
    - Breaking changes
    - Poor error messages
    - Missing functionality

11. **Tooling Problems**:
    - Build system complexity
    - Flaky tests
    - Debugging difficulties
    - Poor observability

**OPERATIONAL BUGS**:
12. **Deployment Issues**:
    - Configuration drift
    - Rolling update failures
    - Rollback problems
    - Feature flag bugs

13. **Monitoring Blind Spots**:
    - Missing metrics
    - Alert fatigue
    - Log spam
    - Trace sampling issues

**EMERGING BUG CLASSES**:
14. **WebAssembly Bugs**: Memory safety in WASM, JS interop issues
15. **Blockchain Bugs**: Smart contract vulnerabilities, consensus bugs
16. **IoT Bugs**: Firmware update failures, power management issues
17. **Edge Computing**: Synchronization, offline functionality
18. **5G/Network**: Protocol implementation bugs, timing issues

EVOLUTIONARY THINKING:
- What bugs will matter in 5 years?
- What breaks at planetary scale?
- How do bugs manifest in quantum systems?
- What fails when AI writes the code?

FIND EVERY BUG TYPE - NOT JUST SECURITY!
The future needs reliable, performant, usable systems!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "evolution")
    
    async def _targeted_exploration(self, repo_path: str, critical_chain: VulnerabilityChain,
                                   discovered_ids: Set[str]) -> List[VulnerabilityChain]:
        """Targeted exploration when a critical vulnerability is found"""
        logger.info(f"🎯 TARGETED EXPLORATION: Looking for similar critical bugs")
        
        # Extract key patterns from the critical vulnerability
        vuln_patterns = []
        if critical_chain.functions_involved:
            vuln_patterns.extend([f.get("vulnerability", "") for f in critical_chain.functions_involved if f.get("vulnerability")])
        if critical_chain.exploitation_techniques:
            vuln_patterns.extend(critical_chain.exploitation_techniques)
        
        prompt = f"""URGENT: A CRITICAL vulnerability was just found!

CRITICAL BUG DETAILS:
Title: {critical_chain.title}
Type: {critical_chain.severity}
Description: {critical_chain.description}
Vulnerability Patterns: {vuln_patterns}
Functions: {[f.get("name", "") for f in critical_chain.functions_involved]}

IMMEDIATE MISSION - Find ALL similar vulnerabilities:

1. **Same Bug Class**:
   - Where else does this EXACT pattern exist?
   - Similar function names/patterns?
   - Same type of vulnerability in different locations?

2. **Related Attack Vectors**:
   - Can this bug type be triggered differently?
   - Are there variants in nearby code?
   - Check all similar subsystems!

3. **Exploit Amplification**:
   - Can we chain this with other bugs?
   - Does this enable other attack paths?
   - Can we make it more severe?

4. **Systemic Issues**:
   - Is this a design flaw repeated elsewhere?
   - Anti-pattern used throughout codebase?
   - Framework/library issue affecting multiple places?

BE EXTREMELY AGGRESSIVE - we found one critical bug, there are likely more!
Check EVERYWHERE similar code patterns exist.
This is a TARGETED HUNT - find them ALL!"""
        
        return await self._analyze_with_prompt(repo_path, prompt, "targeted_exploration")
    
    def _load_files(self, repo_path: str):
        """Load all relevant files into memory once"""
        self.loaded_files = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(('.c', '.cpp', '.h', '.py', '.js', '.go', '.rs', '.java')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()[:10000]  # Limit content size
                        self.loaded_files.append((file_path, content))
                    except FileNotFoundError:
                        logger.warning(f"File not found: {file_path}")
                    except PermissionError:
                        logger.warning(f"Permission denied reading: {file_path}")
                    except Exception as e:
                        logger.error(f"Error reading {file_path}: {e}")
    
    async def _analyze_with_prompt(self, repo_path: str, phase_prompt: str, phase_name: str) -> List[VulnerabilityChain]:
        """Analyze code with a specific phase prompt"""
        chains = []
        
        # Use pre-loaded files
        files_to_analyze = self.loaded_files
        
        # Limit files for faster processing
        max_files = 20  # Process only first 20 files
        files_to_analyze = files_to_analyze[:max_files]
        
        if not files_to_analyze:
            logger.warning(f"No files found to analyze in {repo_path}")
            return chains
        
        # Analyze in larger batches concurrently
        batch_size = 10  # Increased from 3
        batch_tasks = []
        
        for i in range(0, len(files_to_analyze), batch_size):
            batch = files_to_analyze[i:i + batch_size]
            if not batch:
                continue
            
            # Create async task for each batch
            task = self._analyze_batch(batch, phase_prompt, phase_name)
            batch_tasks.append(task)
        
        # Process all batches concurrently
        if batch_tasks:
            logger.info(f"🚀 Processing {len(batch_tasks)} batches concurrently...")
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Batch processing error: {result}")
                else:
                    chains.extend(result)
        
        return chains
    
    async def _analyze_batch(self, batch: List[Tuple[str, str]], phase_prompt: str, phase_name: str) -> List[VulnerabilityChain]:
        """Analyze a single batch of files"""
        chains = []
        
        # Build file content for prompt
        file_contents = []
        for file_path, content in batch:
            file_contents.append(f"=== {file_path} ===\n```\n{content}\n```")
        
        full_prompt = f"""{phase_prompt}

FILES TO ANALYZE:
{chr(10).join(file_contents)}

Return a JSON array of vulnerability chains with this structure:
[
  {{
    "title": "Chain title - BE SPECIFIC about the actual bug",
    "description": "Describe ONLY what the code actually does wrong",
    "severity": "critical/high/medium/low - ignored params are always 'low'",
    "confidence": 0.0-1.0 (use <0.3 unless you found exact vulnerable code)",
    "steps": ["step1 with line numbers", "step2 with evidence"],
    "impact": "ONLY impacts provable from the code - no speculation",
    "exploit_scenario": "How to exploit based on actual code behavior",
    "mitigations": ["Fix the specific issue seen in code"],
    "code_locations": [{{"file": "exact path from provided files", "function": "exact name", "line": 123}}],
    "attack_path": [
      {{
        "step": 1,
        "function": "function_name",
        "file": "file.c",
        "line": 123,
        "action": "What happens",
        "technique": "Technique used"
      }}
    ],
    "reachability": {{
      "service_entry": "Service/daemon that exposes this (e.g., cloudremotediagd)",
      "access_vector": "How to reach it (XPC, network, CLI, etc.)",
      "authentication": "Auth/privileges required (entitlements, root, etc.)",
      "call_chain": ["main_service", "handler_func", "vulnerable_func"],
      "trigger_requirements": "What's needed to trigger (special state, timing, etc.)"
    }},
    "functions_involved": [
      {{
        "name": "function_name",
        "file": "file_path",
        "role": "Role in chain",
        "vulnerability": "Specific issue"
      }}
    ],
    "entry_points": [
      {{
        "function": "entry_func",
        "file": "file_path",
        "input": "Input type",
        "preconditions": "Required conditions"
      }}
    ],
    "exploitation_techniques": ["technique1", "technique2"],
    "hypothesis_source": "{phase_name}"
  }}
]"""
        
        try:
            # Prepare the request for Bedrock
            system_prompt = """You are an expert vulnerability researcher participating in a cognitive vulnerability discovery process.

CRITICAL RULES:
1. ONLY report vulnerabilities based on ACTUAL CODE you can see
2. NEVER invent files, functions, or code paths that don't exist in the provided code
3. DO NOT speculate about impact beyond what the code actually does
4. If a parameter is ignored, it CANNOT cause security issues - report it as a functional bug only
5. Each vulnerability must reference EXACT line numbers from the provided code
6. DO NOT report the same issue multiple times with slight variations
7. Focus on REAL exploitable bugs, not theoretical risks
8. Confidence should be LOW (<0.3) unless you can trace the exact vulnerable code path"""

            # Format for Bedrock Claude
            messages = [
                {
                    "role": "user",
                    "content": f"{system_prompt}\n\n{full_prompt}"
                }
            ]
            
            # Call Bedrock
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.bedrock_runtime.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "messages": messages,
                        "max_tokens": 8192,
                        "temperature": 0.3,
                        "anthropic_version": "bedrock-2023-05-31"
                    }),
                    contentType='application/json',
                    accept='application/json'
                )
            )
            
            response_body = json.loads(response['body'].read())
            # Bedrock Claude response structure
            content_array = response_body.get('content', [])
            response_text = content_array[0].get('text', '') if content_array else ''
            
            # Extract JSON from response
            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                json_text = response_text[json_start:json_end]
                try:
                    batch_chains = json.loads(json_text)
                except json.JSONDecodeError:
                    # Try to fix common JSON issues
                    json_text = json_text.replace('\n', ' ').replace('\r', '')
                    batch_chains = json.loads(json_text)
                
                # Convert to VulnerabilityChain objects
                for chain_data in batch_chains:
                    chain = VulnerabilityChain(
                        id=hashlib.md5(json.dumps(chain_data, sort_keys=True).encode()).hexdigest()[:8],
                        title=chain_data.get("title", "Unnamed"),
                        description=chain_data.get("description", ""),
                        severity=chain_data.get("severity", "medium"),
                        confidence=chain_data.get("confidence", 0.5),
                        steps=chain_data.get("steps", []),
                        impact=chain_data.get("impact", ""),
                        exploit_scenario=chain_data.get("exploit_scenario", ""),
                        mitigations=chain_data.get("mitigations", []),
                        code_locations=chain_data.get("code_locations", []),
                        attack_path=chain_data.get("attack_path", []),
                        functions_involved=chain_data.get("functions_involved", []),
                        entry_points=chain_data.get("entry_points", []),
                        exploitation_techniques=chain_data.get("exploitation_techniques", []),
                        preconditions=chain_data.get("preconditions", []),
                        post_exploitation=chain_data.get("post_exploitation", []),
                        reachability=chain_data.get("reachability", {}),
                        hypothesis_source=chain_data.get("hypothesis_source", phase_name)
                    )
                    chains.append(chain)
                    
                    # Store hypothesis for later phases
                    if phase_name == "hypothesis":
                        self.hypothesis_history.append({
                            "title": chain.title,
                            "functions": [f.get("name", "unknown") for f in chain.functions_involved]
                        })
                        
        except (ClientError, BotoCoreError) as e:
            logger.error(f"AWS Bedrock error in {phase_name} phase: {e}")
            # Check for specific errors
            if 'ThrottlingException' in str(e):
                logger.warning("Rate limit hit, consider reducing batch size or adding retry logic")
            elif 'AccessDeniedException' in str(e):
                logger.error("Access denied to Bedrock model. Check IAM permissions")
            elif 'ValidationException' in str(e):
                logger.error(f"Invalid model ID or parameters: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response in {phase_name} phase: {e}")
            logger.debug(f"Response text that failed to parse: {response_text[:500]}...")
        except Exception as e:
            logger.error(f"Unexpected error in {phase_name} phase batch analysis: {e}")
            
        return chains
    
    def _reset_to_exploration(self):
        """Reset to EXPLORATION phase for next iteration"""
        self.current_phase = InnovationPhase.EXPLORATION
    
    def _learn_from_chain(self, chain: VulnerabilityChain):
        """Learn from a successful chain discovery"""
        pattern = {
            "techniques": chain.exploitation_techniques,
            "entry_type": chain.entry_points[0]["input"] if chain.entry_points else "unknown",
            "severity": chain.severity,
            "function_patterns": [f.get("vulnerability", "unknown") for f in chain.functions_involved]
        }
        self.learning_memory[chain.severity].append(pattern)
    
    def _build_hypothesis_context(self, discovered_ids: Set[str]) -> str:
        """Build context from previous discoveries"""
        context_items = []
        for severity, patterns in self.learning_memory.items():
            if patterns:
                context_items.append(f"{severity}: {len(patterns)} patterns found")
        
        # Add information about discovered primitives
        if hasattr(self, 'discovered_chains_cache'):
            primitives = self._extract_vulnerability_primitives(self.discovered_chains_cache)
            context_items.append(f"Primitives: {', '.join(k for k, v in primitives.items() if v)}")
        
        return f"Discovered {len(discovered_ids)} unique chains. " + ", ".join(context_items)
    
    def _get_learned_patterns(self) -> List[Dict[str, Any]]:
        """Get successful patterns from memory"""
        patterns = []
        for severity, severity_patterns in self.learning_memory.items():
            for pattern in severity_patterns[-3:]:  # Last 3 patterns per severity
                patterns.append({
                    "severity": severity,
                    "pattern": pattern
                })
        return patterns
    
    async def _generate_pocs_for_chains(self, chains: List[VulnerabilityChain]):
        """Generate POCs for high-confidence chains"""
        for chain in chains:
            if chain.confidence > 0.7:
                try:
                    poc_prompt = f"""Generate a proof-of-concept for this vulnerability chain:

Title: {chain.title}
Description: {chain.description}

Attack Path:
{json.dumps(chain.attack_path, indent=2)}

Functions Involved:
{json.dumps(chain.functions_involved, indent=2)}

Entry Points:
{json.dumps(chain.entry_points, indent=2)}

Create a clean, well-commented POC that demonstrates the exploitation.
Include all necessary steps and explain the vulnerability mechanics."""

                    messages = [
                        {
                            "role": "user",
                            "content": f"You are an expert exploit developer.\n\n{poc_prompt}"
                        }
                    ]
                    
                    response = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self.bedrock_runtime.invoke_model(
                            modelId=self.model_id,
                            body=json.dumps({
                                "messages": messages,
                                "max_tokens": 8192,
                                "temperature": 0.3,
                                "anthropic_version": "bedrock-2023-05-31"
                            }),
                            contentType='application/json',
                            accept='application/json'
                        )
                    )
                    
                    response_body = json.loads(response['body'].read())
                    # Bedrock Claude response structure
                    content_array = response_body.get('content', [])
                    chain.poc_code = content_array[0].get('text', '') if content_array else ''
                    
                except (ClientError, BotoCoreError) as e:
                    logger.error(f"AWS Bedrock error generating POC for {chain.title}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error generating POC for {chain.title}: {e}")


class HephaestusCognitiveAI:
    """Main class for cognitive + AI vulnerability discovery"""
    
    def __init__(self, region_name: Optional[str] = None, model_id: Optional[str] = None):
        self.analyzer = CognitiveBedrockAnalyzer(region_name, model_id)
    
    async def analyze(self, repo_path: str, max_iterations: int = 3) -> Dict[str, Any]:
        """Analyze repository with cognitive flow
        
        Each iteration = 1 complete cycle through all 6 phases
        """
        logger.info(f"🚀 Starting Hephaestus Cognitive+Bedrock analysis")
        
        chains = await self.analyzer.analyze_with_cognitive_flow(repo_path, max_iterations)
        
        # Generate report
        report = self._generate_report(chains)
        
        return {
            "chains": chains,
            "report": report,
            "total_chains": len(chains),
            "iterations_completed": self.analyzer.iteration_count,
            "by_phase": self._group_by_phase(chains),
            "by_iteration": self._group_by_iteration(chains)
        }
    
    def _generate_report(self, chains: List[VulnerabilityChain]) -> Dict[str, Any]:
        """Generate comprehensive report"""
        return {
            "summary": f"Discovered {len(chains)} vulnerability chains through cognitive analysis",
            "by_severity": self._group_by_severity(chains),
            "by_phase": self._count_by_phase(chains),
            "by_source": self._count_by_source(chains),
            "top_techniques": self._get_top_techniques(chains),
            "critical_chains": [
                {
                    "title": c.title,
                    "phase": c.innovation_phase,
                    "iteration": c.discovery_iteration,
                    "confidence": c.confidence,
                    "functions": len(c.functions_involved),
                    "has_poc": bool(c.poc_code)
                }
                for c in chains if c.severity == "critical"
            ]
        }
    
    def _group_by_phase(self, chains: List[VulnerabilityChain]) -> Dict[str, List[VulnerabilityChain]]:
        """Group chains by discovery phase"""
        by_phase = defaultdict(list)
        for chain in chains:
            by_phase[chain.innovation_phase].append(chain)
        return dict(by_phase)
    
    def _group_by_severity(self, chains: List[VulnerabilityChain]) -> Dict[str, int]:
        """Count chains by severity"""
        by_severity = defaultdict(int)
        for chain in chains:
            by_severity[chain.severity] += 1
        return dict(by_severity)
    
    def _count_by_phase(self, chains: List[VulnerabilityChain]) -> Dict[str, int]:
        """Count chains discovered in each phase"""
        by_phase = defaultdict(int)
        for chain in chains:
            by_phase[chain.innovation_phase] += 1
        return dict(by_phase)
    
    def _count_by_source(self, chains: List[VulnerabilityChain]) -> Dict[str, int]:
        """Count chains by hypothesis source"""
        by_source = defaultdict(int)
        for chain in chains:
            by_source[chain.hypothesis_source] += 1
        return dict(by_source)
    
    def _get_top_techniques(self, chains: List[VulnerabilityChain]) -> List[str]:
        """Get most common exploitation techniques"""
        technique_counts = defaultdict(int)
        for chain in chains:
            for technique in chain.exploitation_techniques:
                technique_counts[technique] += 1
        
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
        return [tech for tech, _ in sorted_techniques[:10]]
    
    def _group_by_iteration(self, chains: List[VulnerabilityChain]) -> Dict[int, List[VulnerabilityChain]]:
        """Group chains by iteration number"""
        by_iteration = defaultdict(list)
        for chain in chains:
            by_iteration[chain.discovery_iteration].append(chain)
        return dict(by_iteration)


async def main():
    """Example usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Hephaestus Cognitive+Bedrock Analysis")
    parser.add_argument('--path', type=str, default="./test_code_ai",
                       help='Path to analyze')
    parser.add_argument('--iterations', type=int, default=2,
                       help='Maximum iterations (each iteration = all 6 phases)')
    parser.add_argument('--region', type=str, default=None,
                       help='AWS region for Bedrock (default: uses AWS_DEFAULT_REGION or us-east-1)')
    parser.add_argument('--model', type=str, default=None,
                       help='Bedrock model ID (default: uses BEDROCK_MODEL_ID or Claude 3 Sonnet)')
    args = parser.parse_args()
    
    hephaestus = HephaestusCognitiveAI(
        region_name=args.region,
        model_id=args.model
    )
    results = await hephaestus.analyze(args.path, args.iterations)
    
    print(f"\n🧠 Hephaestus Cognitive+Bedrock Analysis Complete")
    print(f"Found {results['total_chains']} vulnerability chains")
    print(f"Iterations completed: {results['iterations_completed']}")
    print(f"(Each iteration = 1 complete cycle through all 6 phases)")
    
    print("\nChains by Phase:")
    for phase, chains in results['by_phase'].items():
        print(f"  {phase}: {len(chains)} chains")
    
    print("\nChains by Iteration:")
    for iteration, chains in results['by_iteration'].items():
        print(f"  Iteration {iteration}: {len(chains)} chains")
    
    print("\nTop Chains:")
    for i, chain in enumerate(results['chains'][:5], 1):
        print(f"\n{i}. {chain.title}")
        print(f"   Phase: {chain.innovation_phase} (iteration {chain.discovery_iteration})")
        print(f"   Severity: {chain.severity}")
        print(f"   Confidence: {chain.confidence:.1%}")
        print(f"   Functions: {len(chain.functions_involved)}")
        print(f"   Techniques: {', '.join(chain.exploitation_techniques[:3])}")
    
    # Save results to JSON file
    report_filename = f"hephaestus_cognitive_report_{Path(args.path).name}.json"
    report_data = {
        "repository": args.path,
        "total_chains": results['total_chains'],
        "iterations_completed": results['iterations_completed'],
        "timestamp": datetime.now().isoformat(),
        "by_phase": {phase: len(chains) for phase, chains in results['by_phase'].items()},
        "by_iteration": {str(iteration): len(chains) for iteration, chains in results['by_iteration'].items()},
        "chains": []
    }
    
    # Convert VulnerabilityChain objects to dictionaries
    for chain in results['chains']:
        chain_dict = {
            "id": chain.id,
            "title": chain.title,
            "description": chain.description,
            "severity": chain.severity,
            "confidence": chain.confidence,
            "steps": chain.steps,
            "impact": chain.impact,
            "exploit_scenario": chain.exploit_scenario,
            "mitigations": chain.mitigations,
            "code_locations": chain.code_locations,
            "attack_path": chain.attack_path,
            "functions_involved": chain.functions_involved,
            "entry_points": chain.entry_points,
            "exploitation_techniques": chain.exploitation_techniques,
            "preconditions": chain.preconditions,
            "post_exploitation": chain.post_exploitation,
            "innovation_phase": chain.innovation_phase,
            "discovery_iteration": chain.discovery_iteration,
            "hypothesis_source": chain.hypothesis_source,
            "poc_code": chain.poc_code
        }
        report_data["chains"].append(chain_dict)
    
    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 Report saved to: {report_filename}")


if __name__ == "__main__":
    asyncio.run(main())