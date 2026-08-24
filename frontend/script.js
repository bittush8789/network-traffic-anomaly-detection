/**
 * NetShield AI - Frontend Controller
 * Handles Chart.js visualizations, real-time live simulation,
 * single packet inspector, MLflow tracking, and filterable telemetry.
 */

// State Management
let timelineChart = null;
let severityChart = null;
let isSimulating = false;
let simulationInterval = null;
let currentPage = 1;
const pageSize = 20;
let totalRecords = 0;
let uploadedFile = null;

// Color Constants
const SEV_COLORS = {
  Critical: '#ff1744',
  High: '#ff9100',
  Medium: '#ffd600',
  Low: '#00e5ff',
  Normal: '#00e676',
};

// DOM Elements
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  fetchStats();
  fetchTimeline();
  fetchLogs();
  setupEventListeners();
  setupPresets();
});

/* ==========================================================================
   Chart Initialization
   ========================================================================== */

function initCharts() {
  // 1. Timeline Chart
  const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(ctxTimeline, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Total Traffic Volume',
          data: [],
          borderColor: '#00f2fe',
          backgroundColor: 'rgba(0, 242, 254, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 2,
        },
        {
          label: 'Anomalies Detected',
          data: [],
          borderColor: '#ff1744',
          backgroundColor: 'rgba(255, 23, 68, 0.2)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
      },
      plugins: {
        legend: {
          labels: { color: '#9ca3af', font: { family: 'Inter', size: 12 } },
        },
        tooltip: {
          backgroundColor: 'rgba(17, 24, 39, 0.95)',
          titleFont: { family: 'Inter', weight: 'bold' },
          bodyFont: { family: 'JetBrains Mono' },
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#6b7280', font: { family: 'JetBrains Mono', size: 10 } },
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#6b7280', font: { family: 'JetBrains Mono', size: 10 } },
        },
      },
    },
  });

  // 2. Severity Donut Chart
  const ctxSeverity = document.getElementById('severityDonutChart').getContext('2d');
  severityChart = new Chart(ctxSeverity, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Normal'],
      datasets: [
        {
          data: [0, 0, 0, 0, 0],
          backgroundColor: [
            SEV_COLORS.Critical,
            SEV_COLORS.High,
            SEV_COLORS.Medium,
            SEV_COLORS.Low,
            SEV_COLORS.Normal,
          ],
          borderColor: '#111827',
          borderWidth: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(17, 24, 39, 0.95)',
          bodyFont: { family: 'Inter' },
        },
      },
      cutout: '72%',
    },
  });
}

/* ==========================================================================
   Data Fetching & API Integrations
   ========================================================================== */

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();

    // Update KPI Cards
    animateValue('kpiTotalFlows', parseInt(data.total_records || 0));
    animateValue('kpiAnomalies', parseInt(data.total_anomalies || 0));
    
    const critAndHigh = (data.severity_counts?.Critical || 0) + (data.severity_counts?.High || 0);
    animateValue('kpiCritical', critAndHigh);
    
    document.getElementById('kpiAnomalyRateSub').innerText = `${data.anomaly_rate_pct || 0}% anomaly rate`;

    // Update Severity Donut
    const sev = data.severity_counts || {};
    document.getElementById('cntCritical').innerText = sev.Critical || 0;
    document.getElementById('cntHigh').innerText = sev.High || 0;
    document.getElementById('cntMedium').innerText = sev.Medium || 0;
    document.getElementById('cntLow').innerText = sev.Low || 0;
    document.getElementById('cntNormal').innerText = sev.Normal || 0;

    severityChart.data.datasets[0].data = [
      sev.Critical || 0,
      sev.High || 0,
      sev.Medium || 0,
      sev.Low || 0,
      sev.Normal || 0,
    ];
    severityChart.update();

    // Update Top Suspicious IPs list
    renderTopIps(data.top_suspicious_ips || []);
  } catch (err) {
    console.error('Error fetching stats:', err);
  }
}

async function fetchTimeline() {
  try {
    const res = await fetch('/api/timeline?points=24');
    if (!res.ok) return;
    const data = await res.json();

    const labels = data.map((d) => d.time);
    const volumes = data.map((d) => d.traffic_volume);
    const anomalies = data.map((d) => d.anomalies);

    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = volumes;
    timelineChart.data.datasets[1].data = anomalies;
    timelineChart.update();
  } catch (err) {
    console.error('Error fetching timeline:', err);
  }
}

async function fetchLogs() {
  const searchIp = document.getElementById('filterSearchIp').value.trim();
  const severity = document.getElementById('filterSeverity').value;
  const protocol = document.getElementById('filterProtocol').value;
  const anomalyOnly = document.getElementById('filterAnomalyOnly').checked;

  const offset = (currentPage - 1) * pageSize;
  const queryParams = new URLSearchParams({
    limit: pageSize,
    offset: offset,
    anomaly_only: anomalyOnly,
  });

  if (searchIp) queryParams.append('search_ip', searchIp);
  if (severity && severity !== 'all') queryParams.append('severity', severity);
  if (protocol && protocol !== 'all') queryParams.append('protocol', protocol);

  try {
    const res = await fetch(`/api/logs?${queryParams.toString()}`);
    if (!res.ok) return;
    const data = await res.json();

    totalRecords = data.total || 0;
    renderTable(data.items || []);
    updatePaginationControls();
  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

/* ==========================================================================
   UI Renderers
   ========================================================================== */

function renderTable(items) {
  const tbody = document.getElementById('trafficTableBody');
  tbody.innerHTML = '';

  if (!items || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center py-4 text-muted">No network records match the specified filters.</td></tr>`;
    return;
  }

  items.forEach((row) => {
    const tr = document.createElement('tr');

    const formattedTime = row.timestamp
      ? new Date(row.timestamp).toLocaleTimeString()
      : '--:--:--';
    const sevClass = `sev-${(row.severity || 'Normal').toLowerCase()}`;
    const isHighRisk = row.anomaly_score >= 70;

    tr.innerHTML = `
      <td>${formattedTime}</td>
      <td><strong>${escapeHtml(row.src_ip)}</strong>:${row.src_port}</td>
      <td><strong>${escapeHtml(row.dst_ip)}</strong>:${row.dst_port}</td>
      <td><span class="proto-tag">${escapeHtml(row.protocol)}</span></td>
      <td>${row.packet_count} / ${formatBytes(row.byte_count)}</td>
      <td>${row.duration}s</td>
      <td><code>${escapeHtml(row.flag)}</code></td>
      <td class="score-cell ${isHighRisk ? 'high-risk' : ''}">${row.anomaly_score}</td>
      <td><span class="severity-badge ${sevClass}">${row.severity}</span></td>
      <td><span class="behavior-badge">${escapeHtml(row.anomaly_type)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderTopIps(ips) {
  const container = document.getElementById('topIpsList');
  container.innerHTML = '';

  if (!ips || ips.length === 0) {
    container.innerHTML = '<div class="empty-state">No suspicious IPs recorded</div>';
    return;
  }

  ips.forEach((item) => {
    const div = document.createElement('div');
    div.className = 'top-ip-row';
    div.innerHTML = `
      <span class="top-ip-val">${escapeHtml(item.ip)}</span>
      <div>
        <span class="top-ip-count">${item.count} anomalies</span>
      </div>
    `;
    container.appendChild(div);
  });
}

function addIncidentFeedItem(flow) {
  const feed = document.getElementById('incidentFeed');
  if (feed.querySelector('.empty-state')) {
    feed.innerHTML = '';
  }

  const item = document.createElement('div');
  item.className = 'incident-item';
  item.innerHTML = `
    <div class="incident-info">
      <span class="incident-type">${escapeHtml(flow.anomaly_type)}</span>
      <span class="incident-meta">${escapeHtml(flow.src_ip)} &rarr; ${escapeHtml(flow.dst_ip)}:${flow.dst_port} (${flow.protocol})</span>
    </div>
    <span class="severity-badge sev-${flow.severity.toLowerCase()}">${flow.severity}</span>
  `;

  feed.prepend(item);
  // Keep maximum 10 incident cards
  while (feed.children.length > 10) {
    feed.removeChild(feed.lastChild);
  }
}

function updatePaginationControls() {
  const totalPages = Math.ceil(totalRecords / pageSize) || 1;
  document.getElementById('currentPageNum').innerText = `Page ${currentPage} of ${totalPages}`;
  document.getElementById('paginationInfo').innerText = `Showing ${Math.min(totalRecords, (currentPage - 1) * pageSize + 1)} - ${Math.min(totalRecords, currentPage * pageSize)} of ${totalRecords} records`;

  document.getElementById('prevPageBtn').disabled = currentPage <= 1;
  document.getElementById('nextPageBtn').disabled = currentPage >= totalPages;
}

/* ==========================================================================
   Single Packet Flow Form & Presets
   ========================================================================== */

function setupPresets() {
  document.getElementById('quickTestDDoSBtn').addEventListener('click', () => {
    document.getElementById('srcIp').value = '198.51.100.44';
    document.getElementById('dstIp').value = '192.168.1.10';
    document.getElementById('protocol').value = 'TCP';
    document.getElementById('srcPort').value = '52194';
    document.getElementById('dstPort').value = '80';
    document.getElementById('flag').value = 'S0';
    document.getElementById('packetCount').value = '8500';
    document.getElementById('byteCount').value = '540000';
    document.getElementById('duration').value = '0.045';
    document.getElementById('failedConns').value = '0';
    showToast('Loaded DDoS Spike test preset', 'info');
  });

  document.getElementById('quickTestPortScanBtn').addEventListener('click', () => {
    document.getElementById('srcIp').value = '203.0.113.88';
    document.getElementById('dstIp').value = '192.168.1.50';
    document.getElementById('protocol').value = 'TCP';
    document.getElementById('srcPort').value = '41200';
    document.getElementById('dstPort').value = '22';
    document.getElementById('flag').value = 'S0';
    document.getElementById('packetCount').value = '2';
    document.getElementById('byteCount').value = '120';
    document.getElementById('duration').value = '0.005';
    document.getElementById('failedConns').value = '1';
    showToast('Loaded Port Scan probe preset', 'info');
  });

  document.getElementById('quickTestBruteBtn').addEventListener('click', () => {
    document.getElementById('srcIp').value = '45.154.255.7';
    document.getElementById('dstIp').value = '192.168.1.50';
    document.getElementById('protocol').value = 'TCP';
    document.getElementById('srcPort').value = '38920';
    document.getElementById('dstPort').value = '22';
    document.getElementById('flag').value = 'REJ';
    document.getElementById('packetCount').value = '45';
    document.getElementById('byteCount').value = '3200';
    document.getElementById('duration').value = '6.5';
    document.getElementById('failedConns').value = '18';
    showToast('Loaded Brute-Force SSH preset', 'info');
  });
}

async function handleSinglePacketEvaluation(e) {
  e.preventDefault();
  const form = document.getElementById('singlePacketForm');
  const formData = new FormData(form);

  const payload = {
    src_ip: formData.get('src_ip'),
    dst_ip: formData.get('dst_ip'),
    protocol: formData.get('protocol'),
    src_port: parseInt(formData.get('src_port')),
    dst_port: parseInt(formData.get('dst_port')),
    packet_count: parseInt(formData.get('packet_count')),
    byte_count: parseInt(formData.get('byte_count')),
    duration: parseFloat(formData.get('duration')),
    flag: formData.get('flag'),
    failed_connections: parseInt(formData.get('failed_connections')),
  };

  try {
    const res = await fetch('/api/predict/single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) throw new Error('Evaluation failed');
    const result = await res.json();

    // Update Result Gauge Box
    const scoreElem = document.getElementById('evalScore');
    scoreElem.innerText = result.anomaly_score;

    const circle = document.getElementById('scoreCircle');
    circle.className = 'score-circle';
    if (result.severity === 'Critical') circle.classList.add('critical');
    else if (result.severity === 'High') circle.classList.add('high');
    else if (result.severity === 'Medium') circle.classList.add('medium');

    const sevBadge = document.getElementById('evalSeverity');
    sevBadge.className = `severity-badge sev-${result.severity.toLowerCase()}`;
    sevBadge.innerText = result.severity;

    document.getElementById('evalDiagnosis').innerText = result.anomaly_type;
    document.getElementById('evalLatency').innerText = `${result.latency_ms} ms`;

    const flagPill = document.getElementById('evalAnomalyFlag');
    if (result.is_anomaly) {
      flagPill.className = 'status-pill anomaly';
      flagPill.innerText = 'ANOMALY DETECTED';
      addIncidentFeedItem(result);
    } else {
      flagPill.className = 'status-pill';
      flagPill.innerText = 'NORMAL TRAFFIC';
    }

    showToast(`Flow evaluated: ${result.severity} (${result.anomaly_type})`, result.is_anomaly ? 'error' : 'success');

    // Refresh Dashboard Telemetry
    fetchStats();
    fetchLogs();
  } catch (err) {
    showToast('Failed to evaluate flow: ' + err.message, 'error');
  }
}

/* ==========================================================================
   Real-Time Traffic Simulator
   ========================================================================== */

function toggleLiveSimulation() {
  const btn = document.getElementById('liveSimToggleBtn');
  const btnText = document.getElementById('simBtnText');
  const badge = document.getElementById('systemStatusBadge');
  const statusText = document.getElementById('statusText');

  if (!isSimulating) {
    isSimulating = true;
    btn.classList.remove('btn-outline-cyan');
    btn.classList.add('btn-primary');
    btnText.innerText = 'Stop Simulator';
    badge.classList.add('sim-active');
    statusText.innerText = 'LIVE STREAMING';
    showToast('Live Network Simulator Started', 'success');

    simulationInterval = setInterval(async () => {
      try {
        const res = await fetch('/api/simulate/traffic', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ count: 2 }),
        });
        if (!res.ok) return;
        const data = await res.json();

        // If any anomalous flows were generated, push to incident feed
        if (data.flows) {
          data.flows.forEach((f) => {
            if (f.is_anomaly) {
              addIncidentFeedItem(f);
            }
          });
        }

        fetchStats();
        fetchTimeline();
        fetchLogs();
      } catch (err) {
        console.error('Simulator stream error:', err);
      }
    }, 1800);
  } else {
    isSimulating = false;
    clearInterval(simulationInterval);
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-outline-cyan');
    btnText.innerText = 'Live Simulator';
    badge.classList.remove('sim-active');
    statusText.innerText = 'SYSTEM ONLINE';
    showToast('Live Network Simulator Stopped', 'info');
  }
}

/* ==========================================================================
   Batch CSV Upload Handling
   ========================================================================== */

function setupUploadModal() {
  const modal = document.getElementById('uploadModal');
  const openBtn = document.getElementById('uploadModalOpenBtn');
  const closeBtn = document.getElementById('uploadModalCloseBtn');
  const cancelBtn = document.getElementById('uploadCancelBtn');
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('csvFileInput');
  const submitBtn = document.getElementById('uploadSubmitBtn');

  openBtn.addEventListener('click', () => modal.classList.add('active'));
  closeBtn.addEventListener('click', () => modal.classList.remove('active'));
  cancelBtn.addEventListener('click', () => modal.classList.remove('active'));

  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleSelectedFile(e.target.files[0]);
    }
  });

  function handleSelectedFile(file) {
    if (!file.name.endsWith('.csv')) {
      showToast('Please select a valid .csv file', 'error');
      return;
    }
    uploadedFile = file;
    document.getElementById('fileNamePreview').innerText = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    submitBtn.disabled = false;
  }

  submitBtn.addEventListener('click', async () => {
    if (!uploadedFile) return;

    const progressWrap = document.getElementById('uploadProgressContainer');
    const progressBar = document.getElementById('uploadProgressBar');
    const summaryBox = document.getElementById('uploadResultSummary');

    progressWrap.style.display = 'block';
    progressBar.style.width = '40%';
    submitBtn.disabled = true;

    const formData = new FormData();
    formData.append('file', uploadedFile);

    try {
      progressBar.style.width = '70%';
      const res = await fetch('/api/predict/batch', {
        method: 'POST',
        body: formData,
      });

      progressBar.style.width = '100%';

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Batch analysis failed');
      }

      const result = await res.json();
      summaryBox.innerHTML = `
        <div style="background: rgba(0, 230, 118, 0.1); border: 1px solid var(--sev-normal); padding: 0.75rem; border-radius: 6px; color: #fff;">
          <strong>Batch Ingestion Successful!</strong><br>
          Processed: <strong>${result.total_records_processed}</strong> flows |
          Anomalies Detected: <strong style="color: var(--sev-critical)">${result.anomalies_detected}</strong> (${result.anomaly_rate_pct}%)
        </div>
      `;

      showToast(`Processed ${result.total_records_processed} flows!`, 'success');
      fetchStats();
      fetchTimeline();
      fetchLogs();
    } catch (err) {
      summaryBox.innerHTML = `<div style="color: var(--sev-critical)">Error: ${err.message}</div>`;
      showToast(err.message, 'error');
    }
  });
}

/* ==========================================================================
   Model Retraining & MLflow Runs Modal
   ========================================================================== */

function setupTrainModal() {
  const modal = document.getElementById('trainModal');
  const openBtn = document.getElementById('trainModalOpenBtn');
  const closeBtn = document.getElementById('trainModalCloseBtn');
  const sliderContam = document.getElementById('sliderContamination');
  const lblContam = document.getElementById('lblContamination');
  const sliderEst = document.getElementById('sliderEstimators');
  const lblEst = document.getElementById('lblEstimators');
  const startBtn = document.getElementById('startTrainingBtn');

  openBtn.addEventListener('click', () => {
    modal.classList.add('active');
    fetchModelRuns();
  });
  closeBtn.addEventListener('click', () => modal.classList.remove('active'));

  sliderContam.addEventListener('input', (e) => {
    lblContam.innerText = e.target.value;
  });

  sliderEst.addEventListener('input', (e) => {
    lblEst.innerText = e.target.value;
  });

  startBtn.addEventListener('click', async () => {
    const contam = parseFloat(sliderContam.value);
    const est = parseInt(sliderEst.value);
    const useDb = document.getElementById('chkUseDb').checked;

    startBtn.disabled = true;
    startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Training & Logging to MLflow...';

    try {
      const res = await fetch('/api/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          n_estimators: est,
          contamination: contam,
          use_existing_db: useDb,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Training failed');
      }

      const result = await res.json();
      showToast('Isolation Forest Retrained & Logged to MLflow!', 'success');
      document.getElementById('kpiModelParams').innerText = `Contam: ${contam} | Trees: ${est}`;

      fetchModelRuns();
      fetchStats();
      fetchLogs();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      startBtn.disabled = false;
      startBtn.innerHTML = '<i class="fa-solid fa-gears"></i> Retrain & Log to MLflow';
    }
  });
}

async function fetchModelRuns() {
  const container = document.getElementById('runsList');
  try {
    const res = await fetch('/api/mlflow/runs');
    if (!res.ok) return;
    const runs = await res.json();

    if (!runs || runs.length === 0) {
      container.innerHTML = '<div class="empty-state">No training runs recorded yet.</div>';
      return;
    }

    container.innerHTML = '';
    runs.forEach((r) => {
      const div = document.createElement('div');
      div.className = 'run-card';
      const timeStr = r.timestamp ? new Date(r.timestamp).toLocaleString() : '--';
      div.innerHTML = `
        <div class="run-card-header">
          <span>${r.model_name} (Trees: ${r.n_estimators}, Contam: ${r.contamination})</span>
          <span style="color: var(--sev-normal)">${r.status}</span>
        </div>
        <div style="color: var(--text-muted); margin: 0.25rem 0;">${timeStr} | Samples: ${r.num_samples} | Detected: ${r.num_anomalies_detected} (${r.anomaly_rate_pct}%)</div>
        <div class="run-card-id"><i class="fa-solid fa-tag"></i> MLflow Run: ${r.mlflow_run_id ? r.mlflow_run_id.substring(0, 16) + '...' : 'Local'}</div>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    console.error('Error fetching model runs:', err);
  }
}

/* ==========================================================================
   Event Listeners & Utilities
   ========================================================================== */

function setupEventListeners() {
  // Live Simulator toggle
  document.getElementById('liveSimToggleBtn').addEventListener('click', toggleLiveSimulation);

  // Single Packet Form
  document.getElementById('singlePacketForm').addEventListener('submit', handleSinglePacketEvaluation);

  // Timeline Refresh
  document.getElementById('refreshTimelineBtn').addEventListener('click', () => {
    fetchTimeline();
    fetchStats();
    showToast('Timeline refreshed', 'info');
  });

  // Table Filters
  document.getElementById('applyFiltersBtn').addEventListener('click', () => {
    currentPage = 1;
    fetchLogs();
  });

  document.getElementById('filterSearchIp').addEventListener('keyup', (e) => {
    if (e.key === 'Enter') {
      currentPage = 1;
      fetchLogs();
    }
  });

  // Pagination
  document.getElementById('prevPageBtn').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      fetchLogs();
    }
  });

  document.getElementById('nextPageBtn').addEventListener('click', () => {
    currentPage++;
    fetchLogs();
  });

  // Clear DB
  document.getElementById('clearDbBtn').addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear all network telemetry records?')) {
      try {
        const res = await fetch('/api/data/clear', { method: 'DELETE' });
        if (res.ok) {
          showToast('Traffic history cleared successfully', 'info');
          fetchStats();
          fetchTimeline();
          fetchLogs();
        }
      } catch (err) {
        showToast('Failed to clear database', 'error');
      }
    }
  });

  setupUploadModal();
  setupTrainModal();
}

function animateValue(id, endValue) {
  const elem = document.getElementById(id);
  if (!elem) return;
  elem.innerText = Number(endValue).toLocaleString();
}

function formatBytes(bytes, decimals = 2) {
  if (!+bytes) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i] || 'TB'}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = type === 'error' ? 'fa-triangle-exclamation' : type === 'success' ? 'fa-circle-check' : 'fa-info-circle';
  toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
