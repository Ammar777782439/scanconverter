package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/template"

	"github.com/Ammar777782439/scanconverter/pkg/models"
)

// HTMLExporter generates a premium HTML report.
type HTMLExporter struct{}

func NewHTMLExporter() *HTMLExporter {
	return &HTMLExporter{}
}

// reportData is passed to the HTML template.
type reportData struct {
	TotalTargets int
	TotalFindings int
	PortsOpen int
	Vulnerabilities int
	FindingsJSON string // For frontend JS (table & charts)
}

func (e *HTMLExporter) Export(results ...*models.ScanResult) ([]byte, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no results to export")
	}

	data := reportData{}
	var allFindings []models.Finding

	for _, r := range results {
		if r == nil {
			continue
		}
		r.BuildSummary()
		data.TotalTargets += r.Summary.TotalTargets
		data.TotalFindings += r.Summary.TotalFindings
		data.PortsOpen += r.Summary.PortsOpen
		data.Vulnerabilities += r.Summary.Vulnerabilities
		allFindings = append(allFindings, r.Findings...)
	}

	b, err := json.Marshal(allFindings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal findings for html: %w", err)
	}
	data.FindingsJSON = string(b)

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse html template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute html template: %w", err)
	}

	return buf.Bytes(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScanConverter Premium Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.1);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #22c55e;
            --glow: 0 0 20px rgba(56, 189, 248, 0.2);
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.1) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            min-height: 100vh;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
            animation: fadeInDown 1s ease-out;
        }

        .header h1 {
            font-size: 3rem;
            font-weight: 800;
            margin: 0;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        /* Glassmorphism Cards */
        .glass-card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .glass-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--glow);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
            animation: fadeInUp 0.8s ease-out;
        }

        .stat-item {
            text-align: center;
        }

        .stat-item h3 {
            margin: 0;
            color: var(--text-secondary);
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-item p {
            margin: 0.5rem 0 0 0;
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--accent);
        }

        /* Charts Layout */
        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
            animation: fadeInUp 1s ease-out;
        }

        .chart-wrapper {
            position: relative;
            height: 300px;
            width: 100%;
        }

        /* Table Styles */
        .table-container {
            width: 100%;
            overflow-x: auto;
            border-radius: 12px;
            animation: fadeInUp 1.2s ease-out;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th, td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background-color: rgba(0, 0, 0, 0.2);
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
            position: sticky;
            top: 0;
        }

        tr:hover {
            background-color: rgba(255, 255, 255, 0.03);
        }

        /* Badges */
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge.high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge.medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge.low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
        .badge.info { background: rgba(34, 197, 94, 0.2); color: var(--info); border: 1px solid var(--info); }
        .badge.unknown { background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); border: 1px solid var(--text-secondary); }

        /* Search Bar */
        .search-wrapper {
            margin-bottom: 1rem;
            display: flex;
            justify-content: flex-end;
        }

        .search-input {
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.75rem 1.5rem;
            border-radius: 9999px;
            font-size: 1rem;
            width: 300px;
            transition: border-color 0.3s;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent);
        }

        /* Animations */
        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>

    <div class="header">
        <h1>ScanConverter Analytics</h1>
        <p>Premium Penetration Testing Report</p>
    </div>

    <!-- KPI Stats -->
    <div class="stats-grid">
        <div class="glass-card stat-item">
            <h3>Targets</h3>
            <p>{{.TotalTargets}}</p>
        </div>
        <div class="glass-card stat-item">
            <h3>Total Findings</h3>
            <p>{{.TotalFindings}}</p>
        </div>
        <div class="glass-card stat-item">
            <h3>Open Ports</h3>
            <p>{{.PortsOpen}}</p>
        </div>
        <div class="glass-card stat-item">
            <h3>Vulnerabilities</h3>
            <p style="color: var(--critical)">{{.Vulnerabilities}}</p>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-container">
        <div class="glass-card">
            <h3 style="text-align: center; color: var(--text-secondary);">Severity Distribution</h3>
            <div class="chart-wrapper">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        <div class="glass-card">
            <h3 style="text-align: center; color: var(--text-secondary);">Finding Types</h3>
            <div class="chart-wrapper">
                <canvas id="typeChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="glass-card table-container">
        <div class="search-wrapper">
            <input type="text" id="searchInput" class="search-input" placeholder="Search findings..." onkeyup="filterTable()">
        </div>
        <table id="findingsTable">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Target (IP/URL)</th>
                    <th>Port/Proto</th>
                    <th>Name / Service</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <!-- Populated by JS -->
            </tbody>
        </table>
    </div>

    <!-- Application Logic -->
    <script>
        const rawFindings = {{.FindingsJSON}};
        
        // 1. Process Data for Charts
        const sevCounts = { critical:0, high:0, medium:0, low:0, info:0, unknown:0 };
        const typeCounts = {};

        rawFindings.forEach(f => {
            const sev = (f.severity || 'unknown').toLowerCase();
            if(sevCounts[sev] !== undefined) sevCounts[sev]++;
            else sevCounts['unknown']++;

            const type = f.type || 'unknown';
            typeCounts[type] = (typeCounts[type] || 0) + 1;
        });

        // 2. Render Severity Chart (Doughnut)
        const ctxSev = document.getElementById('severityChart').getContext('2d');
        new Chart(ctxSev, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'],
                datasets: [{
                    data: [sevCounts.critical, sevCounts.high, sevCounts.medium, sevCounts.low, sevCounts.info, sevCounts.unknown],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e', '#94a3b8'],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#f8fafc' } }
                }
            }
        });

        // 3. Render Type Chart (Bar)
        const ctxType = document.getElementById('typeChart').getContext('2d');
        new Chart(ctxType, {
            type: 'bar',
            data: {
                labels: Object.keys(typeCounts),
                datasets: [{
                    label: 'Count',
                    data: Object.values(typeCounts),
                    backgroundColor: '#38bdf8',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });

        // 4. Render Table
        const tbody = document.getElementById('tableBody');
        
        function renderTable(data) {
            tbody.innerHTML = '';
            data.forEach(f => {
                const tr = document.createElement('tr');
                
                // Severity Badge
                const sev = (f.severity || 'unknown').toLowerCase();
                const sevClass = sevCounts[sev] !== undefined ? sev : 'unknown';
                
                // Target
                const target = f.url || f.ip || f.hostname || f.target || '-';
                
                // Port
                const port = f.port ? f.port + '/' + (f.protocol||'tcp') : '-';

                // Name/Service
                const name = f.name || f.service || f.vuln_id || '-';

                tr.innerHTML = '<td><span class="badge ' + sevClass + '">' + sev + '</span></td>' +
                               '<td style="text-transform: uppercase; font-size:0.85rem;">' + (f.type || '-') + '</td>' +
                               '<td>' + target + '</td>' +
                               '<td>' + port + '</td>' +
                               '<td>' + name + '</td>';
                tbody.appendChild(tr);
            });
        }

        renderTable(rawFindings);

        // 5. Client-side Search
        function filterTable() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const filtered = rawFindings.filter(f => {
                return JSON.stringify(f).toLowerCase().includes(query);
            });
            renderTable(filtered);
        }
    </script>
</body>
</html>`
