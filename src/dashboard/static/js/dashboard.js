const POLL_INTERVAL_MS = 2000;

let protocolChart = null;
let timelineChart = null;

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const idx = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    return `${(bytes / Math.pow(1024, idx)).toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function showError(msg) {
    const banner = document.getElementById("errorBanner");
    if (!msg) {
        banner.classList.add("hidden");
        banner.textContent = "";
        return;
    }
    banner.textContent = msg;
    banner.classList.remove("hidden");
}

function initCharts() {
    const protoCtx = document.getElementById("protocolChart").getContext("2d");
    protocolChart = new Chart(protoCtx, {
        type: "doughnut",
        data: {
            labels: ["TCP", "UDP", "ICMP", "ARP", "Other"],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ["#00d4ff", "#2ecc71", "#f5a623", "#9b59b6", "#8b9bb4"],
                borderColor: "#161d2f",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: "#e8ecf2" } }
            }
        }
    });

    const timelineCtx = document.getElementById("timelineChart").getContext("2d");
    timelineChart = new Chart(timelineCtx, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Packets / sec",
                data: [],
                borderColor: "#00d4ff",
                backgroundColor: "rgba(0, 212, 255, 0.15)",
                tension: 0.25,
                fill: true,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: "#8b9bb4", maxTicksLimit: 8 }, grid: { color: "rgba(255,255,255,0.05)" } },
                y: { beginAtZero: true, ticks: { color: "#8b9bb4" }, grid: { color: "rgba(255,255,255,0.05)" } }
            },
            plugins: {
                legend: { labels: { color: "#e8ecf2" } }
            }
        }
    });
}

async function loadInterfaces() {
    try {
        const res = await fetch("/api/interfaces");
        const interfaces = await res.json();
        const select = document.getElementById("interfaceSelect");
        select.innerHTML = '<option value="">Auto-select interface</option>';
        interfaces.forEach((iface) => {
            const opt = document.createElement("option");
            opt.value = iface.name;
            opt.textContent = iface.ip ? `${iface.name} (${iface.ip})` : iface.name;
            select.appendChild(opt);
        });
    } catch (err) {
        console.error("Failed to load interfaces", err);
    }
}

async function refreshStatus() {
    const res = await fetch("/api/status");
    const status = await res.json();
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");
    const startBtn = document.getElementById("startBtn");
    const stopBtn = document.getElementById("stopBtn");

    if (status.capturing) {
        dot.classList.add("active");
        text.textContent = `Capturing on ${status.interface || "default"} (${status.duration}s)`;
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        dot.classList.remove("active");
        text.textContent = "Idle";
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }

    if (status.error) {
        showError(status.error);
    }
}

async function refreshStats() {
    const res = await fetch("/api/stats");
    const stats = await res.json();

    document.getElementById("totalPackets").textContent = stats.total_packets ?? 0;
    document.getElementById("totalBytes").textContent = formatBytes(stats.total_bytes ?? 0);
    document.getElementById("packetsPerSec").textContent = stats.packets_per_second ?? 0;
    document.getElementById("totalAlerts").textContent = stats.alert_summary?.total_alerts ?? 0;

    const dist = stats.protocol_distribution || {};
    const labels = ["TCP", "UDP", "ICMP", "ARP", "Other"];
    protocolChart.data.datasets[0].data = labels.map((lbl) => dist[lbl] || 0);
    protocolChart.update("none");

    renderIpList("topSourcesList", stats.top_sources || []);
    renderIpList("topDestinationsList", stats.top_destinations || []);
}

function renderIpList(elementId, items) {
    const list = document.getElementById(elementId);
    if (!items.length) {
        list.innerHTML = '<li class="muted">No traffic recorded yet</li>';
        return;
    }
    list.innerHTML = items
        .slice(0, 6)
        .map(([ip, count]) => `<li><span>${ip}</span><span>${count}</span></li>`)
        .join("");
}

async function refreshTimeline() {
    const res = await fetch("/api/stats/timeline?points=60");
    const timeline = await res.json();
    timelineChart.data.labels = timeline.map((item) => item.time);
    timelineChart.data.datasets[0].data = timeline.map((item) => item.packets);
    timelineChart.update("none");
}

async function refreshPackets() {
    const res = await fetch("/api/packets?limit=50");
    const packets = await res.json();
    const tbody = document.getElementById("packetTableBody");

    if (!packets.length) {
        tbody.innerHTML = '<tr><td colspan="9" class="muted">Waiting for packets...</td></tr>';
        return;
    }

    tbody.innerHTML = packets.map((pkt) => {
        const ports = pkt.source_port || pkt.destination_port
            ? `${pkt.source_port || "?"} → ${pkt.destination_port || "?"}`
            : "-";
        const proto = pkt.application_protocol
            ? `${pkt.protocol} (${pkt.application_protocol})`
            : pkt.protocol;
        return `
            <tr>
                <td>${pkt.id ?? ""}</td>
                <td>${(pkt.timestamp || "").slice(11, 19)}</td>
                <td>${pkt.source_ip || "-"}</td>
                <td>${pkt.destination_ip || "-"}</td>
                <td>${ports}</td>
                <td>${proto}</td>
                <td>${pkt.packet_size ?? 0} B</td>
                <td>${pkt.direction || "unknown"}</td>
                <td>${pkt.info || ""}</td>
            </tr>
        `;
    }).join("");
}

async function refreshAlerts() {
    const res = await fetch("/api/alerts?limit=50");
    const alerts = await res.json();
    const container = document.getElementById("alertsContainer");

    if (!alerts.length) {
        container.innerHTML = '<p class="muted">No suspicious activity detected.</p>';
        return;
    }

    container.innerHTML = alerts.map((alert) => `
        <div class="alert-item ${alert.severity}">
            <div class="alert-meta">
                <strong>[${alert.severity}] ${alert.alert_type}</strong>
                <span>${alert.timestamp}</span>
            </div>
            <div>${alert.description}</div>
        </div>
    `).join("");
}

async function refreshDns() {
    const res = await fetch("/api/dns");
    const data = await res.json();
    const stats = data.stats || {};
    const queries = data.queries || [];

    document.getElementById("dnsSummaryBadge").textContent =
        `${stats.total_queries || 0} Queries | ${stats.unique_domains || 0} Domains`;

    const tbody = document.getElementById("dnsTableBody");
    if (!queries.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="muted">No DNS queries captured yet.</td></tr>';
        return;
    }

    tbody.innerHTML = queries.slice(0, 25).map((q) => `
        <tr>
            <td>${(q.timestamp || "").slice(11, 19)}</td>
            <td>${q.source_ip || "-"}</td>
            <td>${q.dns_server || "-"}</td>
            <td>${q.query_domain}</td>
            <td>${q.query_type || "A"}</td>
            <td>${q.response_ip || "-"}</td>
        </tr>
    `).join("");
}

async function pollDashboard() {
    try {
        await Promise.all([
            refreshStatus(),
            refreshStats(),
            refreshTimeline(),
            refreshPackets(),
            refreshAlerts(),
            refreshDns()
        ]);
    } catch (err) {
        console.error("Dashboard polling error", err);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    loadInterfaces();
    pollDashboard();
    setInterval(pollDashboard, POLL_INTERVAL_MS);

    document.getElementById("startBtn").addEventListener("click", async () => {
        showError("");
        const iface = document.getElementById("interfaceSelect").value;
        const res = await fetch("/api/capture/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: iface || null })
        });
        const data = await res.json();
        if (!res.ok) {
            showError(data.message || "Failed to start capture.");
        }
        await refreshStatus();
    });

    document.getElementById("stopBtn").addEventListener("click", async () => {
        showError("");
        const res = await fetch("/api/capture/stop", { method: "POST" });
        const data = await res.json();
        if (!res.ok) {
            showError(data.message || "Failed to stop capture.");
        }
        await refreshStatus();
    });
});
