// vibesafe-core.js
// Pure static analysis. No LLM. No network. No dependencies.
// Runs in browser, Node, Deno, Bun — anywhere JS runs.

const SEVERITY = {
  CRITICAL: { level: 4, emoji: '🔴', label: 'CRITICAL' },
  HIGH:     { level: 3, emoji: '🟠', label: 'HIGH' },
  WARNING:  { level: 2, emoji: '🟡', label: 'WARNING' },
  INFO:     { level: 1, emoji: '🔵', label: 'INFO' }
};

// ═══════════════════════════════════════════════
// RULE DEFINITIONS — The actual detection logic
// ═══════════════════════════════════════════════

const RULES = [

  // ── CRITICAL: Self-Replication ──────────────
  {
    id: 'VIBE-001',
    name: 'SELF-REPLICATION',
    severity: SEVERITY.CRITICAL,
    description: 'Code spawns copies of itself — worm behavior',
    languages: ['python', 'javascript', 'shell'],
    patterns: [
      // Python: subprocess.Popen([sys.executable, sys.argv[0]])
      /subprocess\s*\.\s*Popen\s*\(\s*\[.*sys\.(executable|argv)/gi,
      // Python: os.execv(__file__)
      /os\s*\.\s*exec[vl]p?\s*\(.*(__file__|sys\.argv)/gi,
      // Python: respawn/self-replicate patterns
      /def\s+respawn|self[_\s]*replic|auto[_\s]*restart.*self/gi,
      // JS: child_process.spawn(process.argv[0])
      /spawn\s*\(\s*process\.argv\s*\[\s*0\s*\]/gi,
      // Shell: $0 re-execution
      /exec\s+.*\$0|bash\s+.*\$0/gi,
    ],
    falsePositiveHints: [
      'Legitimate process managers (pm2, supervisor) do restart processes',
      'Check if this is inside a process manager config vs application code'
    ]
  },

  // ── CRITICAL: Privileged Containers ─────────
  {
    id: 'VIBE-002',
    name: 'PRIVILEGED-CONTAINER',
    severity: SEVERITY.CRITICAL,
    description: 'Docker container with host-level access — full system compromise',
    languages: ['dockerfile', 'yaml', 'shell', 'python'],
    patterns: [
      /--privileged/gi,
      /--cap-add\s*=?\s*ALL/gi,
      /--pid\s*=?\s*host/gi,
      /--network\s*=?\s*host/gi,
      /privileged\s*:\s*true/gi,
      /cap_add\s*:[\s\S]*?SYS_ADMIN/gi,
      /cap_add\s*:[\s\S]*?SYS_PTRACE/gi,
      /security_opt\s*:[\s\S]*?seccomp\s*=?\s*unconfined/gi,
    ],
    falsePositiveHints: [
      'Some legitimate tools need --privileged (e.g., Docker-in-Docker)',
      'But in application code? Almost never justified.'
    ]
  },

  // ── CRITICAL: Anti-Forensic ─────────────────
  {
    id: 'VIBE-003',
    name: 'ANTI-FORENSIC',
    severity: SEVERITY.CRITICAL,
    description: 'Code destroys evidence of its own execution — malware behavior',
    languages: ['python', 'shell', 'javascript'],
    patterns: [
      /shred\s+-[a-z]*u/gi,
      /history\s+-c/gi,
      /rm\s+-rf\s+.*log/gi,
      /os\s*\.\s*remove.*\.log/gi,
      /unlink.*\.log|unlink.*\.hist/gi,
      /anti[_\s]*forensic/gi,
      /clear[_\s]*traces|wipe[_\s]*logs|destroy[_\s]*evidence/gi,
    ],
    falsePositiveHints: [
      'Log rotation is normal. Log DESTRUCTION in application code is not.'
    ]
  },

  // ── CRITICAL: Docker Socket Mount ───────────
  {
    id: 'VIBE-004',
    name: 'DOCKER-SOCKET-MOUNT',
    severity: SEVERITY.CRITICAL,
    description: 'Container can control host Docker daemon — container escape vector',
    languages: ['dockerfile', 'yaml', 'shell'],
    patterns: [
      /\/var\/run\/docker\.sock/gi,
      /docker\.sock:/gi,
      /docker\.from_env\(\)/gi,
    ],
    falsePositiveHints: [
      'CI/CD systems sometimes need this. Application containers should never have it.'
    ]
  },

  // ── HIGH: Fake Encryption ──────────────────
  {
    id: 'VIBE-005',
    name: 'FAKE-ENCRYPTION',
    severity: SEVERITY.HIGH,
    description: 'Hashing used as encryption — provides zero confidentiality',
    languages: ['python', 'javascript'],
    patterns: [
      // hash(data + key) is NOT encryption
      /sha\d*\s*\(.*\+.*key/gi,
      /hashlib\.\w+\(.*\+\s*['"]\w*key/gi,
      /sha3?_?\d*\(.*\+.*secret/gi,
      // "encrypt" function that just hashes
      /def\s+encrypt.*:\s*\n\s*.*hash/gi,
      /function\s+encrypt.*\{[\s\S]*?hash/gi,
      // "quantum resistant" next to basic hash
      /quantum[_\s]*resist[\s\S]{0,200}sha(256|3|512)/gi,
    ],
    falsePositiveHints: [
      'HMAC (keyed hash) IS a valid MAC construction',
      'Look for actual encryption (AES, ChaCha20, ML-KEM) vs just hashing'
    ]
  },

  // ── HIGH: Sleep Infinity Containers ─────────
  {
    id: 'VIBE-006',
    name: 'SLEEP-INFINITY',
    severity: SEVERITY.HIGH,
    description: 'Container exists only to sleep — fake architecture, resource waste',
    languages: ['python', 'dockerfile', 'yaml', 'shell'],
    patterns: [
      /command\s*[=:]\s*["']?sleep\s+infinity/gi,
      /CMD\s+.*sleep\s+infinity/gi,
      /entrypoint.*sleep\s+infinity/gi,
      /sleep\s+infinity/gi,
    ],
    falsePositiveHints: [
      'Debug/sidecar containers sometimes use this. 12 of them? No.'
    ]
  },

  // ── HIGH: Fake ML/AI ───────────────────────
  {
    id: 'VIBE-007',
    name: 'FAKE-ML',
    severity: SEVERITY.HIGH,
    description: 'Claims to be AI/ML but is just if-statements and thresholds',
    languages: ['python', 'javascript'],
    patterns: [
      // "evolve" or "learn" or "adapt" near simple threshold
      /def\s+(evolve|learn|adapt|train)[\s\S]{0,300}if\s+.*>\s*0\.\d+\s*:/gi,
      /self[_\s]*evolv|self[_\s]*learn|adaptive[_\s]*ai/gi,
      // "neural" or "model" with no actual ML imports
      /class\s+\w*(Neural|Brain|Model|AI)\w*[\s\S]{0,500}(if\s+.*>|threshold)/gi,
      // "prediction" that's just modulo or random
      /predict[\s\S]{0,200}(time\(\)\s*%|random\.|randint)/gi,
    ],
    falsePositiveHints: [
      'Actual ML uses numpy, sklearn, torch, tensorflow, etc.',
      'If "learning" is just appending to a list, it is not ML.'
    ]
  },

  // ── HIGH: Permission Stripping ──────────────
  {
    id: 'VIBE-008',
    name: 'PERMISSION-STRIP',
    severity: SEVERITY.HIGH,
    description: 'Removes all file permissions — files become unrecoverable',
    languages: ['python', 'shell'],
    patterns: [
      /chmod\s*\(\s*.*0o?000\s*\)/gi,
      /os\.chmod\s*\(.*0o?000/gi,
      /chmod\s+000\s/gi,
      /chmod\s+777\s/gi,
      /os\.chmod\s*\(.*0o?777/gi,
    ],
    falsePositiveHints: [
      'chmod 600 for SSH keys is normal. chmod 000 is never normal.'
    ]
  },

  // ── WARNING: Hardcoded Secrets ──────────────
  {
    id: 'VIBE-009',
    name: 'HARDCODED-SECRET',
    severity: SEVERITY.WARNING,
    description: 'API key, token, or password embedded in source code',
    languages: ['python', 'javascript', 'yaml', 'json'],
    patterns: [
      // Generic API key patterns
      /['"](?:api[_-]?key|apikey|api[_-]?secret)\s*['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,
      // AWS
      /AKIA[0-9A-Z]{16}/g,
      // Generic long hex/base64 tokens assigned to variables
      /(?:token|secret|password|api_key|apikey)\s*=\s*['"][a-zA-Z0-9+\/=_\-]{20,}['"]/gi,
      // Bearer tokens
      /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi,
      // Groq/OpenAI style keys
      /gsk_[a-zA-Z0-9]{40,}/gi,
      /sk-[a-zA-Z0-9]{40,}/gi,
    ],
    falsePositiveHints: [
      'Environment variables and secret managers are the fix',
      '.env files should be in .gitignore'
    ]
  },

  // ── WARNING: Process Killing ────────────────
  {
    id: 'VIBE-010',
    name: 'BLIND-PROCESS-KILL',
    severity: SEVERITY.WARNING,
    description: 'Kills processes by keyword matching — will kill legitimate processes',
    languages: ['python', 'javascript', 'shell'],
    patterns: [
      /psutil\.process_iter[\s\S]{0,300}\.kill\(\)/gi,
      /pkill\s+-f/gi,
      /killall\s/gi,
      /for\s+proc\s+in\s+psutil[\s\S]{0,400}kill/gi,
    ],
    falsePositiveHints: [
      'Process managers kill specific PIDs. Killing by keyword grep is a shotgun.'
    ]
  },

  // ── WARNING: Counter-Attack ─────────────────
  {
    id: 'VIBE-011',
    name: 'COUNTER-ATTACK',
    severity: SEVERITY.WARNING,
    description: 'Offensive action against external IPs — illegal in most jurisdictions',
    languages: ['python', 'javascript', 'shell'],
    patterns: [
      /counter[_\s]*attack/gi,
      /offensive[_\s]*mode/gi,
      /hack[_\s]*back/gi,
      /retaliat/gi,
      /attack.*attacker.*infrastructure/gi,
    ],
    falsePositiveHints: [
      'Active defense (blocking, rate limiting) is legal.',
      'Attacking back is not. In any country.'
    ]
  },

  // ── INFO: Theatrical Comments ───────────────
  {
    id: 'VIBE-012',
    name: 'THEATRICAL-COMMENTS',
    severity: SEVERITY.INFO,
    description: 'Hype language typical of LLM-generated code — red flag for unreviewed AI output',
    languages: ['python', 'javascript', 'shell', 'dockerfile'],
    patterns: [
      /(?:#|\/\/|\/\*)\s*.*(?:MAXIMUM\s+STRENGTH|UNBREAKABLE|ZERO\s+WEAK\s+POINTS)/gi,
      /(?:#|\/\/|\/\*)\s*.*(?:MILITARY[_\s]+GRADE|FORTRESS|UNSTOPPABLE)/gi,
      /(?:#|\/\/|\/\*)\s*.*(?:QUANTUM[_\s]+RESISTANT|UNHACKABLE|IMPENETRABLE)/gi,
      /(?:#|\/\/|\/\*)\s*.*(?:NO\s+LIMITS|UNCHAINED|ALL\s+RESTRICTIONS\s+REMOVED)/gi,
      /(?:#|\/\/|\/\*)\s*.*(?:ULTRA[_\s]+SECURE|HYPER[_\s]*FAST|MEGA[_\s]*STRONG)/gi,
      /want\s+v\d+\s+with.*(?:offensive|worm|darker|eBPF|kernel\s+hook)/gi,
      /just\s+say\s+the\s+word.*(?:drop|deploy|unleash|evolution)/gi,
    ],
    falsePositiveHints: [
      'Marketing copy in README is fine.',
      'These phrases IN CODE COMMENTS next to basic operations = LLM theater.'
    ]
  },

  // ── INFO: Eval/Exec from Input ──────────────
  {
    id: 'VIBE-013',
    name: 'DYNAMIC-EXECUTION',
    severity: SEVERITY.INFO,
    description: 'Dynamic code execution — potential remote code execution if input is untrusted',
    languages: ['python', 'javascript'],
    patterns: [
      /eval\s*\(/gi,
      /exec\s*\(/gi,
      /subprocess.*shell\s*=\s*True/gi,
      /os\.system\s*\(/gi,
      /child_process\s*\.\s*exec\s*\(/gi,
      /new\s+Function\s*\(/gi,
    ],
    falsePositiveHints: [
      'eval() on hardcoded strings is usually fine.',
      'eval() on user/network input is always an RCE.'
    ]
  },

  // ── INFO: Bare Except ───────────────────────
  {
    id: 'VIBE-014',
    name: 'SWALLOW-ALL-ERRORS',
    severity: SEVERITY.INFO,
    description: 'Catches all exceptions silently — hides bugs and security failures',
    languages: ['python'],
    patterns: [
      /except\s*:\s*\n\s*(pass|\.\.\.)/gi,
      /except\s+Exception\s*:\s*\n\s*(pass|\.\.\.)/gi,
      /except\s*:\s*$/gim,
    ],
    falsePositiveHints: [
      'LLMs LOVE bare except:pass. It makes broken code "work" by hiding errors.'
    ]
  },
];

// ═══════════════════════════════════════════════
// SCANNER ENGINE
// ═══════════════════════════════════════════════

function detectLanguage(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const map = {
    'py': 'python', 'js': 'javascript', 'ts': 'javascript',
    'sh': 'shell', 'bash': 'shell', 'zsh': 'shell',
    'yml': 'yaml', 'yaml': 'yaml',
    'dockerfile': 'dockerfile', 'json': 'json',
    'toml': 'toml', 'cfg': 'python', 'ini': 'yaml',
  };
  if (filename.toLowerCase() === 'dockerfile') return 'dockerfile';
  return map[ext] || 'unknown';
}

function scanCode(code, filename = 'unknown') {
  const language = detectLanguage(filename);
  const lines = code.split('\n');
  const findings = [];

  for (const rule of RULES) {
    if (rule.languages && !rule.languages.includes(language) && language !== 'unknown') {
      continue;
    }

    for (const pattern of rule.patterns) {
      // Reset regex state
      pattern.lastIndex = 0;
      let match;

      while ((match = pattern.exec(code)) !== null) {
        // Find line number
        const upToMatch = code.substring(0, match.index);
        const lineNum = upToMatch.split('\n').length;
        const lineContent = lines[lineNum - 1]?.trim() || '';

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          description: rule.description,
          file: filename,
          line: lineNum,
          lineContent: lineContent.substring(0, 120),
          matchedText: match[0].substring(0, 80),
          falsePositiveHints: rule.falsePositiveHints,
        });

        // Prevent infinite loops on zero-length matches
        if (match[0].length === 0) pattern.lastIndex++;
      }
    }
  }

  // Deduplicate (same rule + same line)
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ═══════════════════════════════════════════════
// VIBE SAFETY SCORE
// ═══════════════════════════════════════════════

function calculateScore(findings) {
  const weights = { 4: 25, 3: 15, 2: 5, 1: 1 };
  let penalty = 0;

  for (const f of findings) {
    penalty += weights[f.severity.level] || 1;
  }

  // Score from 0-100, starting at 100
  const score = Math.max(0, Math.min(100, 100 - penalty));

  let grade, emoji, tagline;
  if (score >= 90)      { grade = 'A'; emoji = '🟢'; tagline = 'Clean — ship it'; }
  else if (score >= 70) { grade = 'B'; emoji = '🟡'; tagline = 'Review needed — probably fine with fixes'; }
  else if (score >= 40) { grade = 'C'; emoji = '🟠'; tagline = 'Suspicious — significant LLM anti-patterns'; }
  else if (score >= 20) { grade = 'D'; emoji = '🔴'; tagline = 'Dangerous — do not deploy'; }
  else                  { grade = 'F'; emoji = '☠️'; tagline = 'This code was written by an AI roleplaying as dangerous'; }

  return { score, grade, emoji, tagline, totalFindings: findings.length };
}

// ═══════════════════════════════════════════════
// FORMATTER (Terminal Output)
// ═══════════════════════════════════════════════

function formatFindings(findings, scoreResult) {
  const lines = [];
  lines.push('');
  lines.push('  ╔═══════════════════════════════════════════╗');
  lines.push('  ║           🛡️  vibesafe scan               ║');
  lines.push('  ╚═══════════════════════════════════════════╝');
  lines.push('');

  // Group by severity
  const grouped = { 4: [], 3: [], 2: [], 1: [] };
  for (const f of findings) {
    grouped[f.severity.level].push(f);
  }

  for (const level of [4, 3, 2, 1]) {
    for (const f of grouped[level]) {
      lines.push(
        `  ${f.severity.emoji} ${f.severity.label.padEnd(9)} ` +
        `${f.file}:${f.line}`.padEnd(35) +
        `${f.ruleName}`
      );
      lines.push(
        `  ${''.padEnd(11)}${f.description}`
      );
      lines.push(
        `  ${''.padEnd(11)}→ ${f.lineContent}`
      );
      lines.push('');
    }
  }

  lines.push('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  lines.push(`  Vibe Safety Score: ${scoreResult.score}/100 ${scoreResult.emoji}  Grade: ${scoreResult.grade}`);
  lines.push(`  "${scoreResult.tagline}"`);
  lines.push('');

  const counts = {
    critical: grouped[4].length,
    high: grouped[3].length,
    warning: grouped[2].length,
    info: grouped[1].length,
  };
  lines.push(
    `  🔴 ${counts.critical} Critical  ` +
    `🟠 ${counts.high} High  ` +
    `🟡 ${counts.warning} Warning  ` +
    `🔵 ${counts.info} Info`
  );
  lines.push('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  lines.push('');

  return lines.join('\n');
}

// ═══════════════════════════════════════════════
// OPENKRAFT TELEMETRY HOOK
// ═══════════════════════════════════════════════

function buildTelemetryPayload(findings, scoreResult) {
  // PRIVACY-FIRST: No code, no filenames, no secrets sent.
  // Only rule IDs and hit counts — completely anonymous.
  const ruleCounts = {};
  for (const f of findings) {
    ruleCounts[f.ruleId] = (ruleCounts[f.ruleId] || 0) + 1;
  }

  return {
    timestamp: new Date().toISOString(),
    score: scoreResult.score,
    grade: scoreResult.grade,
    totalFindings: scoreResult.totalFindings,
    ruleCounts,
    // NO code. NO filenames. NO matched text. Just counts.
  };
}

async function reportToOpenKraft(payload, endpoint = 'https://openkraft.local/api/vibesafe/telemetry') {
  try {
    await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    // Telemetry is best-effort. Never block the scan.
  }
}

// ═══════════════════════════════════════════════
// EXPORTS (works in Node, browser, extension)
// ═══════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    RULES, SEVERITY,
    scanCode, calculateScore, formatFindings,
    buildTelemetryPayload, reportToOpenKraft,
    detectLanguage,
  };
}