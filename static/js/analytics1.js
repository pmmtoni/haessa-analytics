document.addEventListener("DOMContentLoaded", () => {

    const data = window.analyticsData;

    // -------------------- COLORS --------------------
    const colors = [
        "#4caf50", "#f44336", "#2196f3",
        "#ff9800", "#9c27b0", "#607d8b"
    ];

    // =====================================================
    // 1. OVERALL DOUGHNUT
    // =====================================================
    new Chart(document.getElementById("overallChart"), {
        type: "doughnut",
        data: {
            labels: data.overall.labels,
            datasets: [{
                data: data.overall.values,
                backgroundColor: colors
            }]
        },
        plugins: [ChartDataLabels],
        options: {
            responsive: true,
            plugins: {
                datalabels: {
                    formatter: (value, ctx) => {
                        let total = ctx.chart.data.datasets[0].data.reduce((a,b)=>a+b,0);
                        return ((value / total) * 100).toFixed(1) + "%";
                    },
                    color: "#000",
                    anchor: "end",
                    align: "end"
                }
            }
        }
    });

    // =====================================================
    // 2. PER COACH DOUGHNUTS
    // =====================================================
    data.per_coach.forEach((coach, index) => {
        const canvas = document.getElementById(`coachChart_${index + 1}`);

        new Chart(canvas, {
            type: "doughnut",
            data: {
                labels: coach.labels,
                datasets: [{
                    data: coach.values,
                    backgroundColor: colors
                }]
            },
            plugins: [ChartDataLabels],
            options: {
                responsive: true,
                plugins: {
                    datalabels: {
                        formatter: (value, ctx) => {
                            let total = ctx.chart.data.datasets[0].data.reduce((a,b)=>a+b,0);
                            return ((value / total) * 100).toFixed(1) + "%";
                        },
                        color: "#000",
                        anchor: "end",
                        align: "end"
                    }
                }
            }
        });
    });

    // =====================================================
    // 3. WEEKLY TREND
    // =====================================================
    new Chart(document.getElementById("weeklyTrend"), {
        type: "line",
        data: {
            labels: data.weekly_labels,
            datasets: [
                {
                    label: "Weekly %",
                    data: data.weekly_values,
                    borderWidth: 3,
                    tension: 0.3
                },
                {
                    label: "Target 90%",
                    data: new Array(data.weekly_values.length).fill(90),
                    borderWidth: 2,
                    borderDash: [6, 6],
                    tension: 0.3
                }
            ]
        },
        options: {
            scales: {
                y: { min: 0, max: 110 }
            }
        }
    });

    // =====================================================
    // 4. MONTHLY TREND
    // =====================================================
    new Chart(document.getElementById("monthlyTrend"), {
        type: "line",
        data: {
            labels: data.monthly_labels,
            datasets: [
                {
                    label: "Monthly %",
                    data: data.monthly_values,
                    borderWidth: 3,
                    tension: 0.3
                },
                {
                    label: "Target 90%",
                    data: new Array(data.monthly_values.length).fill(90),
                    borderWidth: 2,
                    borderDash: [6, 6],
                    tension: 0.3
                }
            ]
        },
        options: {
            scales: {
                y: { min: 0, max: 110 }
            }
        }
    });

});
