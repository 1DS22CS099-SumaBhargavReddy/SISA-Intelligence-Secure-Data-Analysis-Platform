/**
 * AI Secure Data Intelligence Platform — Frontend Logic
 * Handles tab switching, file drag-and-drop, API calls,
 * and dynamic result rendering.
 */

// ─── Configuration ──────────────────────────────────────────────────
// Auto-detect: if served from backend, use same origin; otherwise default to localhost:8000
const API_BASE = (window.location.protocol === "file:")
  ? "http://localhost:8000"
  : window.location.origin;

// ─── Global State ───────────────────────────────────────────────────
let currentAnalysisResult = null;

// ─── DOM References ─────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const elements = {
  tabNav: $("#tabNav"),
  analyzeBtn: $("#analyzeBtn"),
  resultsSection: $("#resultsSection"),

  // Inputs
  textInput: $("#textInput"),
  sqlInput: $("#sqlInput"),
  chatInput: $("#chatInput"),
  logInput: $("#logInput"),

  // File upload
  fileDropZone: $("#fileDropZone"),
  fileInput: $("#fileInput"),
  fileInfo: $("#fileInfo"),
  fileName: $("#fileName"),
  fileSize: $("#fileSize"),
  fileRemove: $("#fileRemove"),

  // Log file upload
  logDropZone: $("#logDropZone"),
  logFileInput: $("#logFileInput"),
  logFileInfo: $("#logFileInfo"),
  logFileName: $("#logFileName"),
  logFileSize: $("#logFileSize"),
  logFileRemove: $("#logFileRemove"),

  // Options
  optMask: $("#optMask"),
  optBlock: $("#optBlock"),
  optLog: $("#optLog"),

  // Results
  gaugeFill: $("#gaugeFill"),
  gaugeNumber: $("#gaugeNumber"),
  gaugeLevel: $("#gaugeLevel"),
  gaugeSummary: $("#gaugeSummary"),
  riskPills: $("#riskPills"),
  actionBadge: $("#actionBadge"),
  findingsBody: $("#findingsBody"),
  findingsCount: $("#findingsCount"),
  findingsEmpty: $("#findingsEmpty"),
  insightsList: $("#insightsList"),
  recommendationsList: $("#recommendationsList"),
  anomaliesCard: $("#anomaliesCard"),
  anomaliesList: $("#anomaliesList"),
  logViewer: $("#logViewer"),
  logViewerContent: $("#logViewerContent"),
  metadataCard: $("#metadataCard"),
  metadataGrid: $("#metadataGrid"),
  maskedCard: $("#maskedCard"),
  maskedContent: $("#maskedContent"),
  toast: $("#toast"),
  
  // New UI Elements
  playbookBtn: $("#playbookBtn"),
  playbookSpinner: $("#playbookSpinner"),
  playbookArea: $("#playbookArea"),
  playbookContent: $("#playbookContent"),
  bgPulse: $("#bg-pulse"),
  navPlaybook: $("#navPlaybook"),
  aiHub: $("#aiHub"),
  consultAiBtn: $("#consultAiBtn"),
  aiConsultSpinner: $("#aiConsultSpinner"),
  aiCtaCard: $("#aiCtaCard"),
};

// ─── State ──────────────────────────────────────────────────────────
let activeTab = "text";
let selectedFile = null;
let selectedLogFile = null;
let analysisContent = "";

// ─── Tab Switching ──────────────────────────────────────────────────
elements.tabNav.addEventListener("click", (e) => {
  const btn = e.target.closest(".tab-btn");
  if (!btn) return;

  activeTab = btn.dataset.tab;

  $$(".tab-btn").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");

  $$(".tab-content").forEach((c) => c.classList.remove("active"));
  $(`#content-${activeTab}`).classList.add("active");
});

// ─── File Drag & Drop ──────────────────────────────────────────────
function setupDropZone(dropZone, fileInput, fileInfo, fileNameEl, fileSizeEl, removeBtn, onSelect) {
  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      onSelect(e.dataTransfer.files[0]);
      showFileInfo(fileInfo, fileNameEl, fileSizeEl, e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      onSelect(fileInput.files[0]);
      showFileInfo(fileInfo, fileNameEl, fileSizeEl, fileInput.files[0]);
    }
  });

  removeBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    onSelect(null);
    fileInfo.classList.remove("visible");
    fileInput.value = "";
  });
}

function showFileInfo(infoEl, nameEl, sizeEl, file) {
  nameEl.textContent = file.name;
  sizeEl.textContent = formatBytes(file.size);
  infoEl.classList.add("visible");
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

// Setup file drop zones
setupDropZone(
  elements.fileDropZone, elements.fileInput,
  elements.fileInfo, elements.fileName, elements.fileSize,
  elements.fileRemove, (f) => { selectedFile = f; }
);

setupDropZone(
  elements.logDropZone, elements.logFileInput,
  elements.logFileInfo, elements.logFileName, elements.logFileSize,
  elements.logFileRemove, (f) => { selectedLogFile = f; }
);

// ─── Analyze Button ─────────────────────────────────────────────────
elements.analyzeBtn.addEventListener("click", async () => {
  const options = {
    mask: elements.optMask.checked,
    block_high_risk: elements.optBlock.checked,
    log_analysis: elements.optLog.checked,
  };

  try {
    setLoading(true);

    let result;

    if ((activeTab === "file" && selectedFile) || (activeTab === "log" && selectedLogFile)) {
      // File upload path
      const file = activeTab === "file" ? selectedFile : selectedLogFile;
      result = await uploadFile(file, options);
      analysisContent = "";
    } else {
      // Text content path
      const content = getActiveContent();
      if (!content.trim()) {
        showToast("Please enter some content to analyze", "error");
        setLoading(false);
        return;
      }
      analysisContent = content;
      result = await analyzeContent(content, activeTab, options);
    }

    renderResults(result);
    currentAnalysisResult = result; // Store for AI Hub
    
    // Reset AI Hub visibility on new scan
    elements.aiHub.style.display = "none";
    if (elements.navPlaybook) elements.navPlaybook.style.display = "none";
    elements.aiCtaCard.style.display = "flex";
    
    showToast("Analysis complete!", "success");
  } catch (err) {
    console.error("Analysis error:", err);
    showToast(`Error: ${err.message}`, "error");
  } finally {
    setLoading(false);
  }
});

function getActiveContent() {
  switch (activeTab) {
    case "text": return elements.textInput.value;
    case "sql": return elements.sqlInput.value;
    case "chat": return elements.chatInput.value;
    case "log": return elements.logInput.value;
    default: return "";
  }
}

// ─── API Calls ──────────────────────────────────────────────────────
async function analyzeContent(content, inputType, options) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      input_type: inputType,
      content: content,
      options: options,
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Server error: ${response.status}`);
  }

  return response.json();
}

async function uploadFile(file, options) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("mask", options.mask);
  formData.append("block_high_risk", options.block_high_risk);
  formData.append("log_analysis", options.log_analysis);

  const response = await fetch(`${API_BASE}/upload`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Server error: ${response.status}`);
  }

  return response.json();
}

// ─── Render Results ─────────────────────────────────────────────────
function renderResults(data) {
  elements.resultsSection.classList.add("visible");

  // Scroll to results
  setTimeout(() => {
    elements.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 100);

  renderRiskGauge(data);
  renderActionBadge(data.action);
  renderFindings(data.findings || []);
  // renderInsights is now moved to the AI Hub activation
  renderAnomalies(data.anomalies || []);
  renderLogViewer(data);
  renderMetadata(data.metadata);
  renderMaskedContent(data.masked_content, data.action);
  
  // Ensure playbook area is hidden on new scan
  elements.playbookArea.style.display = "none";
}

// ─── Risk Gauge ─────────────────────────────────────────────────────
function renderRiskGauge(data) {
  const score = data.risk_score || 0;
  const level = data.risk_level || "low";
  const maxScore = Math.max(score, 20); // Scale gauge
  const pct = Math.min(score / maxScore, 1);

  const circumference = 352;
  const offset = circumference - (pct * circumference);

  const colors = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e",
  };

  elements.gaugeFill.style.strokeDashoffset = offset;
  elements.gaugeFill.style.stroke = colors[level] || colors.low;

  // Animate number
  animateNumber(elements.gaugeNumber, score);

  elements.gaugeLevel.textContent = `${level.toUpperCase()} RISK`;
  elements.gaugeLevel.style.color = colors[level] || colors.low;
  elements.gaugeSummary.textContent = data.summary || "";

  // Risk breakdown pills
  const breakdown = data.risk_breakdown || {};
  elements.riskPills.innerHTML = Object.entries(breakdown)
    .filter(([_, count]) => count > 0)
    .map(([level, count]) =>
      `<span class="risk-pill ${level}">${count} ${level}</span>`
    ).join("");
}

function animateNumber(el, target) {
  let current = 0;
  const step = Math.max(1, Math.ceil(target / 30));
  const interval = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(interval);
    }
    el.textContent = current;
  }, 30);
}

// ─── Action Badge ───────────────────────────────────────────────────
function renderActionBadge(action) {
  const icons = { masked: "🔒", blocked: "🚫", allowed: "✅" };
  const labels = { masked: "Masked", blocked: "Blocked", allowed: "Allowed" };

  elements.actionBadge.className = `action-badge ${action || "allowed"}`;
  elements.actionBadge.innerHTML = `${icons[action] || "✅"} ${labels[action] || "Allowed"}`;
}

// ─── Findings Table ─────────────────────────────────────────────────
function renderFindings(findings) {
  if (findings.length === 0) {
    elements.findingsBody.innerHTML = "";
    elements.findingsEmpty.style.display = "block";
    elements.findingsCount.textContent = "";
    return;
  }

  elements.findingsEmpty.style.display = "none";
  elements.findingsCount.textContent = `${findings.length} found`;

  elements.findingsBody.innerHTML = findings.map((f) => `
    <tr>
      <td><span class="finding-type">${escapeHtml(f.label || f.type)}</span></td>
      <td><span class="finding-value" title="${escapeHtml(f.value || "")}">${escapeHtml(truncate(f.value || "—", 30))}</span></td>
      <td><span class="risk-badge ${f.risk}">${f.risk}</span></td>
      <td>${f.line || "—"}</td>
    </tr>
  `).join("");
}

// ─── Insights & Recommendations ─────────────────────────────────────
function renderInsights(insights, recommendations) {
  if (insights.length === 0) {
    elements.insightsList.innerHTML = `
      <div class="empty-state" style="padding: 20px;">
        <div class="empty-state-icon" style="font-size: 1.5rem;">✅</div>
        <div style="font-size: 0.85rem; color: var(--text-muted);">No security issues identified</div>
      </div>`;
  } else {
    elements.insightsList.innerHTML = insights.map((text) => `
      <div class="insight-item">
        <span class="insight-icon">⚡</span>
        <span class="insight-text">${escapeHtml(text)}</span>
      </div>
    `).join("");
  }

  if (recommendations.length > 0) {
    elements.recommendationsList.innerHTML = recommendations.map((text) => `
      <div class="recommendation-item">
        <span style="flex-shrink:0;">💡</span>
        <span class="recommendation-text">${escapeHtml(text)}</span>
      </div>
    `).join("");
  } else {
    elements.recommendationsList.innerHTML = "";
  }
}

// ─── Anomalies ──────────────────────────────────────────────────────
function renderAnomalies(anomalies) {
  if (anomalies.length === 0) {
    elements.anomaliesCard.style.display = "none";
    return;
  }

  elements.anomaliesCard.style.display = "block";
  elements.anomaliesList.innerHTML = anomalies.map((a) => `
    <div class="anomaly-item">
      <div class="anomaly-header">
        <span class="risk-badge ${a.risk}">${a.risk}</span>
        <span class="anomaly-title">${escapeHtml(a.label || a.type)}</span>
      </div>
      <div class="anomaly-detail">${escapeHtml(a.detail || "")}</div>
    </div>
  `).join("");
}

// ─── Log Viewer ─────────────────────────────────────────────────────
function renderLogViewer(data) {
  const content = analysisContent || data.masked_content || "";
  const sensitiveLines = new Set(data.sensitive_lines || []);

  if (!content || data.content_type !== "logs") {
    elements.logViewer.style.display = "none";
    return;
  }

  elements.logViewer.style.display = "block";
  const lines = content.split("\n");

  elements.logViewerContent.innerHTML = lines.map((line, i) => {
    const lineNum = i + 1;
    const isSensitive = sensitiveLines.has(lineNum);
    return `
      <div class="log-line ${isSensitive ? "sensitive" : ""}">
        <span class="log-line-number">${lineNum}</span>
        <span class="log-line-content">${escapeHtml(line || " ")}</span>
        <span class="log-line-marker">${isSensitive ? "⚠️" : ""}</span>
      </div>
    `;
  }).join("");
}

// ─── Metadata ───────────────────────────────────────────────────────
function renderMetadata(metadata) {
  if (!metadata) {
    elements.metadataCard.style.display = "none";
    return;
  }

  elements.metadataCard.style.display = "block";

  const items = [
    { label: "Total Lines", value: metadata.total_lines || 0 },
    { label: "Parsed Lines", value: metadata.parsed_lines || 0 },
    { label: "Unique IPs", value: metadata.unique_ips || 0 },
  ];

  // Add level distribution
  if (metadata.level_distribution) {
    Object.entries(metadata.level_distribution).forEach(([level, count]) => {
      items.push({ label: level, value: count });
    });
  }

  elements.metadataGrid.innerHTML = items.map((item) => `
    <div class="metadata-item">
      <div class="metadata-value">${item.value}</div>
      <div class="metadata-label">${escapeHtml(item.label)}</div>
    </div>
  `).join("");
}

// ─── Masked Content ─────────────────────────────────────────────────
function renderMaskedContent(maskedContent, action) {
  if (!maskedContent || action !== "masked") {
    elements.maskedCard.style.display = "none";
    return;
  }

  elements.maskedCard.style.display = "block";
  elements.maskedContent.textContent = maskedContent;
}

// ─── Utilities ──────────────────────────────────────────────────────
function setLoading(loading) {
  elements.analyzeBtn.classList.toggle("loading", loading);
  elements.analyzeBtn.disabled = loading;
}

function showToast(message, type = "info") {
  elements.toast.textContent = message;
  elements.toast.className = `toast ${type} visible`;
  setTimeout(() => {
    elements.toast.classList.remove("visible");
  }, 4000);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function truncate(str, len) {
  return str.length > len ? str.substring(0, len) + "…" : str;
}

// ─── Keyboard Shortcut ─────────────────────────────────────────────
// ─── AI Playbook Generation ────────────────────────────────────────
elements.playbookBtn.addEventListener("click", async () => {
  if (!currentAnalysisResult) return;
  
  try {
    setPlaybookLoading(true);
    const response = await fetch(`${API_BASE}/playbook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: getActiveContent() || "Analyzed content",
        findings: currentAnalysisResult.findings,
        anomalies: currentAnalysisResult.anomalies
      })
    });
    
    const data = await response.json();
    elements.playbookArea.style.display = "block";
    elements.playbookContent.textContent = data.playbook;
    
    // Show playbook link in navbar
    if (elements.navPlaybook) elements.navPlaybook.style.display = "flex";
    
    elements.playbookArea.scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    showToast("Failed to generate playbook", "error");
  } finally {
    setPlaybookLoading(false);
  }
});

function setPlaybookLoading(loading) {
  elements.playbookBtn.classList.toggle("loading", loading);
  elements.playbookBtn.disabled = loading;
  if (elements.playbookSpinner) elements.playbookSpinner.style.display = loading ? "block" : "none";
}

// ─── 3D Tilt Effect ──────────────────────────────────────────────────
function init3DTilt() {
  const cards = $$('.card');
  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      
      const rotateX = ((y - centerY) / centerY) * -5;
      const rotateY = ((x - centerX) / centerX) * 5;
      
      card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-5px) scale(1.01)`;
    });
    
    card.addEventListener('mouseleave', () => {
      card.style.transform = '';
    });
  });
}

// ─── Cyber-Pulse Background ────────────────────────────────────────
function initCyberPulse() {
  const container = elements.bgPulse;
  if (!container) return;
  
  setInterval(() => {
    const dot = document.createElement('div');
    dot.className = 'pulse-dot';
    dot.style.left = Math.random() * 100 + '%';
    dot.style.top = Math.random() * 100 + '%';
    dot.style.animationDuration = (2 + Math.random() * 3) + 's';
    
    container.appendChild(dot);
    setTimeout(() => dot.remove(), 5000);
  }, 1000);
}

// Initialize New Features
init3DTilt();
initCyberPulse();

// Smooth Scroll for Navbar Links
$$('.nav-link').forEach(link => {
  link.addEventListener('click', (e) => {
    const href = link.getAttribute('href');
    if (href && href.startsWith('#')) {
      e.preventDefault();
      const target = $(href);
      if (target) {
        const offset = 100; // Account for sticky navbar
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - offset;
        window.scrollTo({ top: targetPosition, behavior: 'smooth' });
      }
      
      $$('.nav-link').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
    }
  });
});

document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    elements.analyzeBtn.click();
  }
});

// ─── AI Hub Activation ──────────────────────────────────────────────
if (elements.consultAiBtn) {
  elements.consultAiBtn.addEventListener("click", () => {
    if (!currentAnalysisResult) return;
    
    elements.consultAiBtn.classList.add("loading");
    
    // Artificial delay to simulate "AI Thinking" (Premium Feeling)
    setTimeout(() => {
      elements.aiHub.style.display = "block";
      renderInsights(currentAnalysisResult.insights || [], currentAnalysisResult.recommendations || []);
      
      // Show Playbook button if high risk (score >= 10)
      if (currentAnalysisResult.risk_score >= 10) {
        elements.playbookBtn.style.display = "flex";
      }

      elements.consultAiBtn.classList.remove("loading");
      elements.aiCtaCard.style.display = "none"; // Hide CTA after activation
      
      // Scroll to the AI Hub
      const offset = 100;
      const targetPosition = elements.aiHub.getBoundingClientRect().top + window.pageYOffset - offset;
      window.scrollTo({ top: targetPosition, behavior: 'smooth' });
    }, 1000);
  });
}
