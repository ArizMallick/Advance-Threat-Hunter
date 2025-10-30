// DOM Elements
const startBtn = document.getElementById('startBtn');
const clearBtn = document.getElementById('clearBtn');
const exitBtn = document.getElementById('exitBtn');
const downloadBtn = document.getElementById('downloadBtn');
const uploadBtn = document.getElementById('uploadBtn');
const output = document.getElementById('output');
const statusBadge = document.getElementById('statusBadge');
const statusText = document.getElementById('statusText');
const sessionIdEl = document.getElementById('sessionId');
const uploadResult = document.getElementById('uploadResult');
const fileInput = document.getElementById('logfile');
const fileName = document.getElementById('fileName');
const scanStatus = document.getElementById('scanStatus');
const threatsCount = document.getElementById('threatsCount');
const scanDuration = document.getElementById('scanDuration');

// State variables
let evtSource = null;
let sessionId = null;
let logLines = [];
let isScanning = false;
let scanStartTime = null;
let scanTimer = null;
let detectedThreats = 0;

// Utility Functions
function appendLine(line) {
  logLines.push(line);
  output.textContent += line + '\n';
  output.scrollTop = output.scrollHeight;

  // Count threats
  if (line.includes('⚠️') || line.includes('🚨') || line.includes('ALERT')) {
    detectedThreats++;
    threatsCount.textContent = detectedThreats;
  }
}

function setStatus(text, scanning = false) {
  statusText.textContent = text;
  scanStatus.textContent = text;

  if (scanning) {
    statusBadge.classList.add('scanning');
  } else {
    statusBadge.classList.remove('scanning');
  }
}

function updateScanDuration() {
  if (!scanStartTime) return;

  const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
  const minutes = Math.floor(elapsed / 60);
  const seconds = elapsed % 60;
  scanDuration.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function startDurationTimer() {
  scanStartTime = Date.now();
  scanTimer = setInterval(updateScanDuration, 1000);
}

function stopDurationTimer() {
  if (scanTimer) {
    clearInterval(scanTimer);
    scanTimer = null;
  }
}

// Main Scan Function
async function startScan() {
  if (isScanning) {
    appendLine('⚠️ Scan already in progress.');
    return;
  }

  isScanning = true;
  startBtn.disabled = true;
  detectedThreats = 0;
  threatsCount.textContent = '0';
  setStatus('Initializing...', true);
  output.textContent = '';
  logLines = [];
  startDurationTimer();

  try {
    const res = await fetch('/api/scan', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to start scan (HTTP ' + res.status + ')');

    const json = await res.json();
    sessionId = json.session || json.id || null;
    sessionIdEl.textContent = sessionId ? sessionId.substring(0, 8) + '...' : '—';

    if (typeof EventSource !== 'undefined') {
      const url = '/api/scan/stream?session=' + encodeURIComponent(sessionId || '');
      evtSource = new EventSource(url);

      evtSource.onmessage = (e) => {
        appendLine(e.data);
      };

      evtSource.addEventListener('progress', (e) => {
        appendLine('[PROGRESS] ' + e.data);
      });

      evtSource.addEventListener('done', (e) => {
        appendLine('✅ ' + e.data);
        cleanupStream();
      });

      evtSource.onerror = (e) => {
        appendLine('❗ Stream connection closed.');
        cleanupStream();
      };

      setStatus('Scanning', true);
      appendLine('🔍 System Scan Initiated');
      appendLine('📋 Session: ' + (sessionId || 'unknown').substring(0, 8) + '...');
      appendLine('⏰ Started at: ' + new Date().toLocaleTimeString());
      appendLine('='.repeat(80));

    } else {
      appendLine('ℹ️ EventSource not available. Using polling fallback.');
      pollLogs(sessionId);
    }

  } catch (err) {
    appendLine('❌ Error starting scan: ' + err.message);
    setStatus('Error');
    stopDurationTimer();
    isScanning = false;
    startBtn.disabled = false;
  }
}

// Polling fallback
async function pollLogs(sess) {
  setStatus('Scanning (poll)', true);
  let finished = false;

  while (!finished) {
    try {
      const r = await fetch('/api/scan/logs?session=' + encodeURIComponent(sess || ''));
      if (!r.ok) throw new Error('HTTP ' + r.status);

      const j = await r.json();
      if (Array.isArray(j.lines)) {
        j.lines.forEach(l => appendLine(l));
      }

      if (j.done) {
        appendLine('✅ Scan Complete');
        finished = true;
        setStatus('Idle');
        stopDurationTimer();
        isScanning = false;
        startBtn.disabled = false;
        break;
      }
    } catch (e) {
      appendLine('❗ Poll error: ' + e.message);
      break;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
}

// Cleanup stream
function cleanupStream() {
  if (evtSource) {
    try {
      evtSource.close();
    } catch (e) { }
    evtSource = null;
  }
  setStatus('Idle');
  stopDurationTimer();
  isScanning = false;
  startBtn.disabled = false;
}

// Clear output
function clearOutput() {
  logLines = [];
  output.textContent = '';
  detectedThreats = 0;
  threatsCount.textContent = '0';
  scanDuration.textContent = '00:00';
  appendLine('🗑️ Console cleared. Ready for new scan.');
  appendLine('⏳ Awaiting commands...\n');
}

// Download report
function downloadReport() {
  if (logLines.length === 0) {
    alert('⚠️ No scan data available. Please run a scan first.');
    return;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  const reportHeader = [
    '='.repeat(80),
    'ADVANCED THREAT HUNTER - SECURITY SCAN REPORT',
    '='.repeat(80),
    'Generated: ' + new Date().toLocaleString(),
    'Session ID: ' + (sessionId || 'N/A'),
    'Threats Detected: ' + detectedThreats,
    'Scan Duration: ' + scanDuration.textContent,
    '='.repeat(80),
    '',
    ...logLines,
    '',
    '='.repeat(80),
    'END OF REPORT',
    '='.repeat(80)
  ].join('\n');

  const blob = new Blob([reportHeader], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = sessionId
    ? `threat-report-${sessionId.substring(0, 8)}-${timestamp}.txt`
    : `threat-report-${timestamp}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  appendLine('💾 Security report downloaded successfully.');
}

// Exit application
function exitApp() {
  if (confirm('⚠️ Are you sure you want to exit the application?')) {
    appendLine('👋 Shutting down Advanced Threat Hunter...');
    setTimeout(() => {
      try {
        window.close();
      } catch (e) {
        window.location.href = 'about:blank';
      }
    }, 500);
  }
}

// File selection handler
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    const file = e.target.files[0];
    fileName.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
    uploadBtn.disabled = false;
  } else {
    fileName.textContent = 'No file selected';
    uploadBtn.disabled = true;
  }
});

// File upload handler
uploadBtn.addEventListener('click', async () => {
  if (!fileInput.files.length) {
    alert('⚠️ Please select a file first');
    return;
  }

  uploadResult.style.display = 'block';
  uploadResult.textContent = '⏳ Uploading and analyzing log file...\nPlease wait...';
  uploadBtn.disabled = true;

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);

  try {
    const res = await fetch('/api/scan/upload', { method: 'POST', body: fd });
    if (!res.ok) throw new Error('Upload failed (HTTP ' + res.status + ')');

    const json = await res.json();
    uploadResult.textContent = JSON.stringify(json, null, 2);

    // Append summary to main console
    appendLine('\n' + '='.repeat(80));
    appendLine('📄 LOG FILE ANALYSIS COMPLETE');
    appendLine('='.repeat(80));
    appendLine(`📁 Filename: ${json.filename}`);
    appendLine(`📊 Total Lines Analyzed: ${json.total_lines}`);
    appendLine(`🚨 Threats Found: ${json.matches.length}`);
    appendLine(`   ├─ Keyword Matches: ${json.summary.keyword_matches}`);
    appendLine(`   ├─ IP Addresses: ${json.summary.ip_matches}`);
    appendLine(`   ├─ Base64 Strings: ${json.summary.base64_matches}`);
    appendLine(`   └─ Suspicious Commands: ${json.summary.cmd_matches}`);
    appendLine('='.repeat(80));

    if (json.matches.length > 0) {
      appendLine('\n⚠️ DETAILED THREAT ANALYSIS:');
      appendLine('-'.repeat(80));
      json.matches.slice(0, 10).forEach(m => {
        appendLine(`Line ${m.line_no}: ${m.text.substring(0, 100)}${m.text.length > 100 ? '...' : ''}`);
        m.matches.forEach(match => {
          appendLine(`   └─ [${match.type.toUpperCase()}] ${match.value}`);
        });
      });
      if (json.matches.length > 10) {
        appendLine(`\n... and ${json.matches.length - 10} more matches (see JSON output above)`);
      }
      appendLine('-'.repeat(80));
    } else {
      appendLine('\n✅ No threats detected in the uploaded log file.');
    }

    appendLine('='.repeat(80) + '\n');

  } catch (err) {
    uploadResult.textContent = '❌ Error: ' + err.message;
    appendLine('❌ File upload error: ' + err.message);
  } finally {
    uploadBtn.disabled = false;
  }
});

// Event Listeners
startBtn.addEventListener('click', startScan);
clearBtn.addEventListener('click', clearOutput);
downloadBtn.addEventListener('click', downloadReport);
exitBtn.addEventListener('click', exitApp);

// Initialize
(function init() {
  appendLine('🛡️ Advanced Threat Hunter System Initialized');
  appendLine('✅ Backend API Connection Established');
  appendLine('📡 Endpoint: http://127.0.0.1:4000');
  appendLine('⏰ System Time: ' + new Date().toLocaleString());
  appendLine('🔐 Security Status: Active');
  appendLine('⏳ Ready for commands...\n');
  setStatus('Ready');
})();