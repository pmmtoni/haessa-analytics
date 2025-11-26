# -*- coding: utf-8 -*-
"""
Created on Mon Nov 17 15:32:37 2025

@author: Paul
"""

document.addEventListener('DOMContentLoaded', function () {
  // Draw a tiny textual chart for analytics placeholder
  const el = document.getElementById('overall-chart');
  if (!el) return;
  const labels = JSON.parse(el.dataset.labels || '[]');
  const values = JSON.parse(el.dataset.values || '[]');
  if (!labels.length) {
    el.innerHTML = '<em>No analytics data</em>';
    return;
  }
  const list = document.createElement('ul');
  list.className = 'list-group';
  for (let i = 0; i < labels.length; i++) {
    const li = document.createElement('li');
    li.className = 'list-group-item d-flex justify-content-between align-items-center';
    li.textContent = labels[i];
    const badge = document.createElement('span');
    badge.className = 'badge bg-primary rounded-pill';
    badge.textContent = values[i];
    li.appendChild(badge);
    list.appendChild(li);
  }
  el.appendChild(list);
});
