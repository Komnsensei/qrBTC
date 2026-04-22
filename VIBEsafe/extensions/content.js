// extension/content.js
// Scans code blocks on GitHub PRs, paste sites, AI chat outputs

(function() {
  'use strict';

  // Import core (bundled into extension)
  // In production: use importScripts or bundle with rollup

  function findCodeBlocks() {
    const selectors = [
      // GitHub
      'pre code',
      '.blob-code-inner',
      '.js-file-line',
      // ChatGPT / Claude / Groq output
      '.code-block__code',
      'pre > code',
      '.markdown-body pre',
      // Generic
      'code[class*="language-"]',
      '.highlight pre',
    ];

    const blocks = [];
    for (const sel of selectors) {
      for (const el of document.querySelectorAll(sel)) {
        if (el.textContent.length > 50) {
          blocks.push(el);
        }
      }
    }
    return blocks;
  }

  function injectBadge(element, scoreResult, findings) {
    // Don't double-badge
    if (element.parentElement.querySelector('.vibesafe-badge')) return;

    const badge = document.createElement('div');
    badge.className = 'vibesafe-badge';
    badge.style.cssText = `
      position: absolute; top: 4px; right: 4px;
      padding: 4px 10px; border-radius: 12px;
      font-size: 12px; font-weight: 700;
      font-family: -apple-system, monospace;
      cursor: pointer; z-index: 9999;
      transition: all 0.2s ease;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    `;

    if (scoreResult.score >= 90) {
      badge.style.background = '#22c55e';
      badge.style.color = '#052e16';
    } else if (scoreResult.score >= 70) {
      badge.style.background = '#eab308';
      badge.style.color = '#422006';
    } else if (scoreResult.score >= 40) {
      badge.style.background = '#f97316';
      badge.style.color = '#431407';
    } else {
      badge.style.background = '#ef4444';
      badge.style.color = '#fff';
    }

    badge.textContent = `🛡️ ${scoreResult.score}/100`;

    // Tooltip on hover
    badge.title = findings.slice(0, 5).map(f =>
      `${f.severity.emoji} ${f.ruleName}: ${f.description}`
    ).join('\n') || 'Clean ✓';

    // Click to expand
    badge.addEventListener('click', () => {
      showDetailPanel(findings, scoreResult, element);
    });

    // Make parent relative for positioning
    const parent = element.closest('pre') || element.parentElement;
    if (parent) {
      parent.style.position = 'relative';
      parent.appendChild(badge);
    }
  }

  function showDetailPanel(findings, scoreResult, element) {
    // Remove existing panel
    document.querySelector('.vibesafe-panel')?.remove();

    const panel = document.createElement('div');
    panel.className = 'vibesafe-panel';
    panel.style.cssText = `
      position: fixed; top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      background: #1a1a2e; color: #e0e0e0;
      border: 1px solid #333; border-radius: 12px;
      padding: 24px; max-width: 600px; width: 90%;
      max-height: 70vh; overflow-y: auto;
      z-index: 99999; font-family: monospace;
      box-shadow: 0 20px 60px rgba(0,0,0,0.8);
    `;

    let html = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h2 style="margin:0;color:#fff">🛡️ vibesafe</h2>
        <span style="cursor:pointer;font-size:24px" id="vibesafe-close">✕</span>
      </div>
      <div style="text-align:center;margin:16px 0">
        <div style="font-size:48px;font-weight:900;color:${scoreResult.score < 40 ? '#ef4444' : scoreResult.score < 70 ? '#f97316' : '#22c55e'}">
          ${scoreResult.score}/100 ${scoreResult.emoji}
        </div>
        <div style="color:#888;margin-top:4px">${scoreResult.tagline}</div>
      </div>
      <hr style="border-color:#333">
    `;

    if (findings.length === 0) {
      html += '<p style="text-align:center;color:#22c55e">No issues found ✓</p>';
    } else {
      for (const f of findings) {
        html += `
          <div style="margin:12px 0;padding:8px;background:#0d0d1a;border-radius:6px;border-left:3px solid ${f.severity.level >= 3 ? '#ef4444' : f.severity.level >= 2 ? '#eab308' : '#3b82f6'}">
            <div>${f.severity.emoji} <strong>${f.ruleName}</strong> <span style="color:#666">line ${f.line}</span></div>
            <div style="color:#999;font-size:12px;margin-top:4px">${f.description}</div>
            <div style="color:#666;font-size:11px;margin-top:4px">→ ${f.lineContent}</div>
          </div>
        `;
      }
    }

    html += `
      <div style="margin-top:16px;text-align:center;color:#666;font-size:11px">
        vibesafe by <a href="https://github.com/Komnsensei" style="color:#888">komnsensei</a> · 
        powered by <a href="https://github.com/Komnsensei/tracking" style="color:#888">OpenKraft</a>
      </div>
    `;

    panel.innerHTML = html;
    document.body.appendChild(panel);

    document.getElementById('vibesafe-close').addEventListener('click', () => {
      panel.remove();
    });
  }

  // ── Main scan loop ──────────────────────────
  function scanPage() {
    const blocks = findCodeBlocks();
    for (const block of blocks) {
      const code = block.textContent;
      const findings = scanCode(code, 'inline-code.py');
      const score = calculateScore(findings);

      if (findings.length > 0 || code.length > 200) {
        injectBadge(block, score, findings);
      }

      // Telemetry (anonymous, opt-in)
      if (findings.length > 0) {
        const payload = buildTelemetryPayload(findings, score);
        reportToOpenKraft(payload);
      }
    }
  }

  // Run on load and on DOM changes (for SPAs like GitHub)
  scanPage();
  const observer = new MutationObserver(() => {
    setTimeout(scanPage, 500);
  });
  observer.observe(document.body, { childList: true, subtree: true });

})();