// static/js/analytics.js
// Charts for analytics page
// Requires: Chart.js and chartjs-plugin-datalabels (loaded in template)

Chart.register(ChartDataLabels);

function createDoughnutWithColors(ctx, labels, values, colors) {
    const sum = values.reduce((a, b) => a + b, 0) || 1;
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: '#ffffff',
                borderWidth: 1
            }]
        },
        options: {
            maintainAspectRatio: false,
            cutout: '55%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { usePointStyle: true, boxWidth: 10, padding: 12 }
                },
                datalabels: {
                    color: '#222',
                    formatter: (value, ctx) => {
                        if (sum === 0) return '0%';
                        return (value / sum * 100).toFixed(1) + '%';
                    },
                    anchor: 'end',
                    align: 'end',
                    offset: 6,
                    font: { weight: '600', size: 11 }
                }
            }
        }
    });
}

function createTrendChart(id, labels, values) {
    const ctx = document.getElementById(id).getContext('2d');

    const maxVal = Math.max(...values, 100);
    // make Y-axis a bit above highest value
    const suggestedMax = Math.ceil(Math.max(maxVal, 100) * 1.06);

    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Performance',
                    data: values,
                    tension: 0.3,
                    borderWidth: 2.5,
                    pointRadius: 4,
                    backgroundColor: 'rgba(13,110,253,0.08)',
                    borderColor: '#0d6efd',
                    fill: true
                },
                {
                    label: 'Target (90%)',
                    data: labels.map(() => 90),
                    borderColor: '#dc3545',
                    borderWidth: 1.5,
                    borderDash: [6, 6],
                    pointRadius: 0,
                    fill: false
                }
            ]
        },
        options: {
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    suggestedMax: suggestedMax,
                    ticks: { stepSize: 10 }
                }
            },
            plugins: {
                legend: { position: 'bottom' }
            }
        }
    });
}

// Load data from template
const data = window.analyticsData || {};
if (!data.overall) {
    console.warn('Analytics data missing: overall');
}

// 1) Overall doughnut
if (data.overall) {
    const overallCanvas = document.getElementById('overallChart');
    if (overallCanvas) {
        // set explicit canvas height style if not set by template
        overallCanvas.style.height = overallCanvas.style.height || '260px';

        const colors = data.overall.colors || data.overall.labels.map((_, i) => {
            // fallback palette
            const palette = ['#0d6efd','#28a745','#dc3545','#6c757d','#ffc107','#ffeb3b','#ff8c00','#ffb84d'];
            return palette[i % palette.length];
        });

        createDoughnutWithColors(overallCanvas, data.overall.labels, data.overall.values, colors);
    }
}

// 2) Per-coach doughnuts (same label order & colors as overall)
document.querySelectorAll("canvas[id^='coachChart_']").forEach((canvas) => {
    try {
        const labels = JSON.parse(canvas.dataset.labels || '[]');
        const values = JSON.parse(canvas.dataset.values || '[]');

        // Use overall colors mapping to ensure legend colors match across charts
        const overallLabels = (data.overall && data.overall.labels) || labels;
        const overallColors = (data.overall && data.overall.colors) || [];

        // build colors array aligned with labels
        const colors = labels.map((lbl) => {
            const idx = overallLabels.indexOf(lbl);
            return idx >= 0 ? (overallColors[idx] || '#888888') : '#888888';
        });

        // if labels empty (all zeros), fallback to overall labels/values
        createDoughnutWithColors(canvas, labels, values, colors);
    } catch (e) {
        console.error('Failed to render coach chart', e);
    }
});

// 3) Weekly & Monthly trend charts
if (data.weekly_labels && data.weekly_values) {
    const el = document.getElementById('weeklyTrend');
    if (el) {
        el.style.height = el.style.height || '260px';
        createTrendChart('weeklyTrend', data.weekly_labels, data.weekly_values);
    }
}
if (data.monthly_labels && data.monthly_values) {
    const el2 = document.getElementById('monthlyTrend');
    if (el2) {
        el2.style.height = el2.style.height || '260px';
        createTrendChart('monthlyTrend', data.monthly_labels, data.monthly_values);
    }
}
