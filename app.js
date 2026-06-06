// -------------------------------------------------------------
// AETHERSEC DASHBOARD LOGIC
// Connects UI interaction to Python API server endpoints
// -------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
    // DOM Cache
    const targetInput = document.getElementById("target-input");
    const clearTargetBtn = document.getElementById("clear-target");
    const scanBtn = document.getElementById("scan-btn");
    const fuzzBtn = document.getElementById("fuzz-btn");
    const clearTerminalBtn = document.getElementById("clear-terminal");
    const consoleLogs = document.getElementById("console-logs");
    
    // Panel elements for enabling/disabling
    const targetInfoCard = document.getElementById("target-info-card");
    const headersCard = document.getElementById("headers-card");
    const dnsPortsCard = document.getElementById("dns-ports-card");
    const fuzzCard = document.getElementById("fuzz-card");
    
    // Target Overview fields
    const valDomain = document.getElementById("val-domain");
    const valIp = document.getElementById("val-ip");
    const valSsl = document.getElementById("val-ssl");
    const valIsp = document.getElementById("val-isp");
    const valGeo = document.getElementById("val-geo");
    
    // Headers Card fields
    const gaugeScore = document.getElementById("gauge-score");
    const headerAuditList = document.getElementById("header-audit-list");
    
    // Tabs & Panels
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");
    const dnsContainer = document.getElementById("dns-record-container");
    const portsTableBody = document.getElementById("ports-table-body");
    
    // Fuzz Panel fields
    const fuzzCount = document.getElementById("fuzz-count");
    const fuzzTableBody = document.getElementById("fuzz-table-body");
    
    // Report Builder elements
    const reportForm = document.getElementById("report-form");
    const repTarget = document.getElementById("rep-target");
    const repType = document.getElementById("rep-type");
    const repSeverity = document.getElementById("rep-severity");
    const repPayload = document.getElementById("rep-payload");
    const repDesc = document.getElementById("rep-desc");
    const repRemedy = document.getElementById("rep-remedy");

    // Local state to hold latest scan findings
    let latestScanData = null;

    // Helper: Print formatted console log in the UI console
    function log(message, type = "info") {
        const timestamp = new Date().toLocaleTimeString();
        const line = document.createElement("div");
        line.className = `log-line ${type}`;
        
        // Escape special chars
        const safeMsg = message.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        line.innerHTML = `<span class="time">[${timestamp}]</span> ${safeMsg}`;
        
        consoleLogs.appendChild(line);
        consoleLogs.scrollTop = consoleLogs.scrollHeight;
    }

    // Clear target input
    clearTargetBtn.addEventListener("click", () => {
        targetInput.value = "";
        targetInput.focus();
    });

    // Clear UI logs
    clearTerminalBtn.addEventListener("click", () => {
        consoleLogs.innerHTML = `<div class="log-line system">[SYSTEM] Console cleared. Waiting for actions...</div>`;
    });

    // Tabs switcher
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(btn.dataset.tab).classList.add("active");
        });
    });

    // Function: Run Reconnaissance Scan
    async function runReconScan() {
        const target = targetInput.value.trim();
        if (!target) {
            log("[!] Error: No target domain provided.", "error");
            return;
        }

        // Setup UI state
        scanBtn.disabled = true;
        scanBtn.innerHTML = `<span class="btn-icon"><i class="fa-solid fa-spinner fa-spin"></i></span><span class="btn-text">Scanning...</span>`;
        log(`[*] Initiating reconnaissance scan on: ${target}...`, "info");
        log(`[*] Querying DNS records and security headers...`, "info");

        try {
            const response = await fetch(`/api/scan?target=${encodeURIComponent(target)}`);
            const data = await response.json();

            if (data.error) {
                log(`[!] Scan Error: ${data.error}`, "error");
                return;
            }

            latestScanData = data;
            log(`[+] Active Recon scan completed for: ${data.target}`, "success");
            log(`[+] IP Address resolved: ${data.ip}`, "success");
            
            // Populate UI Components
            populateTargetOverview(data);
            populateHeadersAudit(data);
            populateDNSAndPorts(data);
            
            // Auto fill target in report builder
            repTarget.value = data.target;
            
            // Update Report details based on header count
            updateReportRecommendation(data);
            
        } catch (err) {
            log(`[!] Connection Error: Failed to reach integration backend.`, "error");
            console.error(err);
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `<span class="btn-icon"><i class="fa-solid fa-crosshairs"></i></span><span class="btn-text">Run Recon Scan</span>`;
        }
    }

    // Function: Fuzz Endpoints
    async function runEndpointFuzz() {
        const target = targetInput.value.trim();
        if (!target) {
            log("[!] Error: No target domain provided.", "error");
            return;
        }

        fuzzBtn.disabled = true;
        fuzzBtn.innerHTML = `<span class="btn-icon"><i class="fa-solid fa-spinner fa-spin"></i></span><span class="btn-text">Fuzzing...</span>`;
        log(`[*] Starting fuzzing engine on: ${target}...`, "info");
        log(`[*] Loading payload dictionary (common endpoints & sensitive paths)...`, "info");

        try {
            const response = await fetch(`/api/fuzz?target=${encodeURIComponent(target)}`);
            const results = await response.json();

            if (results.error) {
                log(`[!] Fuzzing Error: ${results.error}`, "error");
                return;
            }

            log(`[+] Fuzzing completed! ${results.length} endpoints discovered.`, "success");
            
            // Populate Fuzzer panel
            populateFuzzResults(results);
            
        } catch (err) {
            log(`[!] Fuzzing connection failure. Verify backend is active.`, "error");
            console.error(err);
        } finally {
            fuzzBtn.disabled = false;
            fuzzBtn.innerHTML = `<span class="btn-icon"><i class="fa-solid fa-magnifying-glass-chart"></i></span><span class="btn-text">Fuzz Endpoints</span>`;
        }
    }

    // Population Helper: Target Overview Card
    function populateTargetOverview(data) {
        targetInfoCard.classList.remove("disabled");
        
        valDomain.textContent = data.target;
        valIp.textContent = data.ip;
        
        // SSL info parsing
        if (data.ssl && !data.ssl.error) {
            valSsl.textContent = `${data.ssl.version} (${data.ssl.days_left} days left)`;
            valSsl.style.color = data.ssl.days_left < 15 ? "var(--color-red)" : "var(--color-green)";
        } else {
            valSsl.textContent = data.ssl && data.ssl.error ? "Failed (No SSL / Port 443 closed)" : "N/A";
            valSsl.style.color = "var(--color-yellow)";
        }
        
        // Geo IP details parsing
        if (data.geoip && data.geoip.status === "success") {
            valIsp.textContent = data.geoip.isp || "Unknown ISP";
            valGeo.textContent = `${data.geoip.city || "Unknown City"}, ${data.geoip.regionName || ""}, ${data.geoip.country || ""}`;
        } else {
            valIsp.textContent = "IP Location Query Failed";
            valGeo.textContent = "N/A";
        }
    }

    // Population Helper: Security Headers Audit
    function populateHeadersAudit(data) {
        headersCard.classList.remove("disabled");
        headerAuditList.innerHTML = "";
        
        if (!data.headers || data.headers.error) {
            gaugeScore.textContent = "0/6";
            gaugeScore.style.color = "var(--color-red)";
            headerAuditList.innerHTML = `<li class="header-item"><span class="header-name">Error fetching headers: ${data.headers ? data.headers.error : "Unknown"}</span></li>`;
            return;
        }

        const analysis = data.headers.analysis;
        let secureCount = 0;
        const totalHeaders = Object.keys(analysis).length;

        for (const [headerName, details] of Object.entries(analysis)) {
            const li = document.createElement("li");
            li.className = "header-item";
            
            const badgeClass = details.present ? "secure" : "missing";
            const badgeLabel = details.present ? "SECURE" : "MISSING";
            
            if (details.present) secureCount++;
            
            li.innerHTML = `
                <span class="header-name" title="${details.description}">${headerName}</span>
                <span class="header-badge ${badgeClass}">${badgeLabel}</span>
            `;
            headerAuditList.appendChild(li);
        }

        gaugeScore.textContent = `${secureCount}/${totalHeaders}`;
        if (secureCount === totalHeaders) {
            gaugeScore.style.color = "var(--color-green)";
            headersCard.style.borderColor = "var(--color-green)";
        } else if (secureCount >= 3) {
            gaugeScore.style.color = "var(--color-yellow)";
            headersCard.style.borderColor = "var(--color-yellow)";
        } else {
            gaugeScore.style.color = "var(--color-red)";
            headersCard.style.borderColor = "var(--color-red)";
        }
        
        log(`[+] Security Headers: ${secureCount} present out of ${totalHeaders}`, secureCount >= 3 ? "success" : "warning");
    }

    // Population Helper: DNS & Ports Card
    function populateDNSAndPorts(data) {
        dnsPortsCard.classList.remove("disabled");
        
        // Render DNS Records
        dnsContainer.innerHTML = "";
        let recordsAdded = false;
        
        if (data.dns) {
            for (const [type, values] of Object.entries(data.dns)) {
                if (values && values.length > 0 && !values[0].includes("Error")) {
                    recordsAdded = true;
                    const card = document.createElement("div");
                    card.className = "dns-card";
                    card.innerHTML = `
                        <div class="dns-type">${type}</div>
                        <div class="dns-values">${values.join("<br>")}</div>
                    `;
                    dnsContainer.appendChild(card);
                }
            }
        }
        
        if (!recordsAdded) {
            dnsContainer.innerHTML = `<div class="log-line system">No active DNS records recovered.</div>`;
        }

        // Render Open Ports
        portsTableBody.innerHTML = "";
        if (data.open_ports && data.open_ports.length > 0) {
            data.open_ports.forEach(port => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${port.port}</td>
                    <td>${port.service}</td>
                    <td><span class="port-status-badge">OPEN</span></td>
                `;
                portsTableBody.appendChild(tr);
            });
            log(`[+] Open Ports found: ${data.open_ports.map(p => p.port).join(", ")}`, "warning");
        } else {
            portsTableBody.innerHTML = `<tr><td colspan="3" class="system" style="text-align: center;">No standard ports open / filtered</td></tr>`;
        }
    }

    // Population Helper: Fuzz results
    function populateFuzzResults(results) {
        fuzzCard.classList.remove("disabled");
        fuzzCount.textContent = `${results.length} Discovered`;
        
        fuzzTableBody.innerHTML = "";
        
        if (results.length === 0) {
            fuzzTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No matching directories or sensitive files discovered.</td></tr>`;
            return;
        }

        results.forEach(res => {
            const tr = document.createElement("tr");
            tr.style.cursor = "pointer";
            tr.title = "Click to load endpoint into Report Builder";
            
            // Add click action to auto load fuzzed item into report builder
            tr.addEventListener("click", () => {
                loadFuzzIntoReport(res);
            });

            const statusClass = `s${res.status}`;
            tr.innerHTML = `
                <td><span style="color: var(--color-cyan)">/${res.path}</span></td>
                <td><span class="fuzz-status-tag ${statusClass}">${res.status}</span></td>
                <td>${res.length} B</td>
                <td>${res.time_ms} ms</td>
            `;
            fuzzTableBody.appendChild(tr);
        });
    }

    // Auto load header audits recommendations into report form
    function updateReportRecommendation(data) {
        if (!data.headers || !data.headers.analysis) return;
        
        const missing = [];
        for (const [header, details] of Object.entries(data.headers.analysis)) {
            if (!details.present) {
                missing.push(header);
            }
        }
        
        if (missing.length > 0) {
            repType.value = "Missing Security Headers";
            repPayload.value = `Target headers not set: ${missing.join(", ")}`;
            
            repDesc.value = `The target web server at ${data.target} is missing critical HTTP Security Headers that mitigate clientside attacks. Specifically, the following headers are missing:\n${missing.map(h => `- ${h}`).join("\n")}\n\nWithout these headers, users are exposed to potential clickjacking, cross-site scripting (XSS), and MIME-type sniffing attacks.`;
            
            repRemedy.value = `Configure the web server (e.g., Apache, Nginx, IIS) or CDN/Gateway to inject the following headers in all responses:\n- Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n- Content-Security-Policy: default-src 'self';\n- X-Frame-Options: SAMEORIGIN\n- X-Content-Type-Options: nosniff\n- Referrer-Policy: strict-origin-when-cross-origin`;
        }
    }

    // Load selected fuzz endpoint details into report builder
    function loadFuzzIntoReport(fuzzItem) {
        repTarget.value = targetInput.value.trim() || new URL(fuzzItem.url).hostname;
        repType.value = "Information Disclosure (Sensitive Files)";
        repSeverity.value = fuzzItem.status === 200 ? "High" : "Medium";
        repPayload.value = fuzzItem.url;
        
        repDesc.value = `An endpoint or sensitive file was discovered on the target server. Accessing the path return HTTP Status Code ${fuzzItem.status}.\n\nPath: ${fuzzItem.path}\nURL: ${fuzzItem.url}\nResponse size: ${fuzzItem.length} bytes.\n\nThis could indicate file disclosure, exposed administration panels, or misconfigured access control schemes.`;
        
        repRemedy.value = `Restructure permissions on the directory/endpoint to restrict public access. Ensure that sensitive administrative scripts, configurations (.env, backups, or git layouts) are deleted or blocklist-filtered via routing engines. Return HTTP 404/403 for unauthorised assets.`;
        
        log(`[*] Loaded /${fuzzItem.path} info into Report Builder.`, "info");
        
        // Scroll to report builder
        reportForm.scrollIntoView({ behavior: 'smooth' });
    }

    // Handle Vulnerability Report Compilation
    reportForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const reportData = {
            target: repTarget.value.trim(),
            vuln_type: repType.value,
            severity: repSeverity.value,
            payload: repPayload.value.trim(),
            description: repDesc.value.trim(),
            remediation: repRemedy.value.trim(),
            date: new Date().toLocaleDateString()
        };
        
        log(`[*] Compiling report for target: ${reportData.target}...`, "info");

        try {
            const response = await fetch("/api/report", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(reportData)
            });
            const data = await response.json();

            if (data.error) {
                log(`[!] Report Compilation Error: ${data.error}`, "error");
                return;
            }

            log(`[+] Report compiled and saved on server: ${data.file_path}`, "success");

            // Trigger client browser file download of the Markdown report
            const blob = new Blob([data.content], { type: "text/markdown" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${reportData.target.replace(/\./g, "_")}_vulnerability_report.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            log(`[+] Vulnerability report downloaded successfully!`, "success");
        } catch (err) {
            log(`[!] Failed to transmit report payload to integration server.`, "error");
            console.error(err);
        }
    });

    // Event Bindings
    scanBtn.addEventListener("click", runReconScan);
    fuzzBtn.addEventListener("click", runEndpointFuzz);

    // Initial console welcome log
    log("[SYSTEM] Connection initialized. Target validation ready.", "success");
});
