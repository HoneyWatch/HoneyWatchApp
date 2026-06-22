/* HoneyWatch dashboard front-end. Fetches JSON from the Flask API and
   renders the interactive map, charts, and heatmap. */
(function () {
  "use strict";

  const COLORS = {
    accent: "#f59e0b",
    accentSoft: "rgba(245, 158, 11, 0.18)",
    red: "#dc2626",
    grid: "rgba(255,255,255,0.05)",
    tick: "#8a8a93",
  };

  const getJSON = (url) => fetch(url).then((r) => r.json());

  function currentRange() {
    const menu = document.getElementById("time-range-menu");
    if (!menu) return "24h";
    const selected = menu.querySelector('[aria-selected="true"]');
    return selected ? selected.dataset.value : "24h";
  }

  function apiUrl(path) {
    const sep = path.includes("?") ? "&" : "?";
    return `${path}${sep}range=${encodeURIComponent(currentRange())}`;
  }

  // Chart instances (so auto-refresh can update in place, no page reload).
  const charts = {};
  let isRefreshing = false;
  let mapFitted = false;

  const RANGE_DELTA = { "1h": "1h", "24h": "24h", week: "7d", month: "30d" };

  function applyChartDefaults() {
    if (typeof Chart === "undefined") return;
    Chart.defaults.color = COLORS.tick;
    Chart.defaults.font.family = "Inter, Segoe UI, system-ui, sans-serif";
    Chart.defaults.font.size = 11;
  }

  /* ---------- Map (Leaflet — lightest fit for a VPS dashboard)
   *  ~40 KB lib via CDN; raster tiles from CARTO (not hosted on VPS).
   *  OpenLayers / MapLibre are 5–10× heavier (WebGL + large bundles). ---------- */
  let attackMap = null;
  let markerLayer = null;

  function setMapInfo(name, count) {
    const el = document.getElementById("map-info");
    if (!el) return;
    if (!name) {
      el.textContent = "Hover an attack source for details";
      return;
    }
    el.innerHTML =
      `<strong>${name}</strong> — ` +
      `<span class="map-info-count">${count.toLocaleString()}</span> attack${count === 1 ? "" : "s"}`;
  }

  function markerRadius(count, min, max) {
    const lo = 6;
    const hi = 26;
    if (max <= min) return (lo + hi) / 2;
    return lo + ((count - min) / (max - min)) * (hi - lo);
  }

  function initMap(points) {
    const el = document.getElementById("attack-map");
    if (!el) return;

    if (typeof L === "undefined") {
      const box = el.parentElement;
      if (box) {
        box.innerHTML =
          '<p class="map-error">Leaflet failed to load. Check your network and hard-refresh (Ctrl+F5).</p>';
      }
      return;
    }

    const valid = points.filter((p) => p.lat != null && p.lng != null);
    if (!valid.length) {
      setMapInfo(null, 0);
      return;
    }

    if (!attackMap) {
      attackMap = L.map(el, {
        center: [22, 12],
        zoom: 2,
        minZoom: 2,
        maxZoom: 6,
        worldCopyJump: true,
        zoomControl: true,
        attributionControl: true,
      });

      // CARTO Dark Matter — matches dashboard theme; tiles offloaded from VPS.
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
          subdomains: "abcd",
          maxZoom: 6,
          detectRetina: false,
          keepBuffer: 1,
        }
      ).addTo(attackMap);

      markerLayer = L.layerGroup().addTo(attackMap);
    } else {
      markerLayer.clearLayers();
    }

    const counts = valid.map((p) => p.count);
    const minC = Math.min(...counts);
    const maxC = Math.max(...counts);

    valid.forEach((p) => {
      const r = markerRadius(p.count, minC, maxC);
      const marker = L.circleMarker([p.lat, p.lng], {
        radius: r,
        fillColor: COLORS.accent,
        color: "#fde68a",
        weight: 1,
        fillOpacity: 0.75,
      });

      marker.on("mouseover", () => setMapInfo(p.name, p.count));
      marker.on("mouseout", () => setMapInfo(null, 0));
      marker.bindTooltip(
        `<strong>${p.name}</strong><br>${p.count.toLocaleString()} attacks`,
        { direction: "top", offset: [0, -Math.round(r)] }
      );

      markerLayer.addLayer(marker);
    });

    // Only fit/zoom on the first render so auto-refresh keeps the user's view.
    if (!mapFitted) {
      const bounds = L.latLngBounds(valid.map((p) => [p.lat, p.lng]));
      if (valid.length === 1) {
        attackMap.setView(bounds.getCenter(), 4);
      } else {
        attackMap.fitBounds(bounds.pad(0.3));
      }
      mapFitted = true;
    }

    requestAnimationFrame(() => attackMap.invalidateSize());
  }

  /* ---------- Charts ---------- */
  function initTimeline(data) {
    const ctx = document.getElementById("timeline-chart");
    if (!ctx) return;

    if (charts.timeline) {
      charts.timeline.data.labels = data.map((d) => d.label);
      charts.timeline.data.datasets[0].data = data.map((d) => d.value);
      charts.timeline.update("none");
      return;
    }

    const grad = ctx.getContext("2d").createLinearGradient(0, 0, 0, 200);
    grad.addColorStop(0, "rgba(245,158,11,0.35)");
    grad.addColorStop(1, "rgba(245,158,11,0.0)");

    charts.timeline = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.map((d) => d.label),
        datasets: [
          {
            data: data.map((d) => d.value),
            borderColor: COLORS.accent,
            backgroundColor: grad,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              maxTicksLimit: data.length > 30 ? 12 : data.length > 14 ? 10 : 7,
              color: COLORS.tick,
            },
          },
          y: {
            grid: { color: COLORS.grid },
            ticks: { maxTicksLimit: 5, color: COLORS.tick },
          },
        },
      },
    });
  }

  function horizontalBars(canvasId, data, color) {
    const el = document.getElementById(canvasId);
    if (!el) return;

    const existing = charts[canvasId];
    if (existing) {
      existing.data.labels = data.map((d) => d.label);
      existing.data.datasets[0].data = data.map((d) => d.value);
      existing.update("none");
      return;
    }

    charts[canvasId] = new Chart(el, {
      type: "bar",
      data: {
        labels: data.map((d) => d.label),
        datasets: [
          {
            data: data.map((d) => d.value),
            backgroundColor: color,
            borderRadius: 3,
            barThickness: 12,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (c) => c.raw.toLocaleString() } },
        },
        scales: {
          x: { grid: { color: COLORS.grid }, ticks: { display: false } },
          y: { grid: { display: false }, ticks: { color: "#cfcfd4" } },
        },
      },
    });
  }

  function initDonut(data) {
    const el = document.getElementById("types-chart");
    if (el) {
      if (charts.types) {
        charts.types.data.labels = data.map((d) => d.label);
        charts.types.data.datasets[0].data = data.map((d) => d.value);
        charts.types.data.datasets[0].backgroundColor = data.map((d) => d.color);
        charts.types.update("none");
      } else {
        charts.types = new Chart(el, {
          type: "doughnut",
          data: {
            labels: data.map((d) => d.label),
            datasets: [
              {
                data: data.map((d) => d.value),
                backgroundColor: data.map((d) => d.color),
                borderWidth: 0,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
              legend: { display: false },
              tooltip: { callbacks: { label: (c) => `${c.raw}%` } },
            },
          },
        });
      }
    }

    const legend = document.getElementById("types-legend");
    if (legend) {
      legend.innerHTML = data
        .map(
          (d) =>
            `<li><span class="legend-dot" style="background:${d.color}"></span>` +
            `<span>${d.label}</span><span class="legend-pct">${d.value}%</span></li>`
        )
        .join("");
    }
  }

  /* ---------- KPIs (updated live on auto-refresh) ---------- */
  function renderDelta(value) {
    const up = value >= 0;
    const arrow = up ? "6 14 12 8 18 14" : "6 10 12 16 18 10";
    const label = RANGE_DELTA[currentRange()] || "24h";
    const sign = value >= 0 ? "+" : "";
    return (
      `<span class="kpi-delta ${up ? "up" : "down"}">` +
      `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" ` +
      `stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">` +
      `<polyline points="${arrow}"/></svg> ` +
      `${sign}${value.toFixed(1)}% (${label})</span>`
    );
  }

  function updateKpis(summary) {
    document.querySelectorAll("[data-kpi]").forEach((card) => {
      const key = card.dataset.kpi;
      const entry = summary[key];
      if (!entry) return;
      const valueEl = card.querySelector("[data-kpi-value]");
      const deltaEl = card.querySelector("[data-kpi-delta]");
      if (valueEl) valueEl.textContent = Number(entry.value).toLocaleString();
      if (deltaEl) deltaEl.innerHTML = renderDelta(Number(entry.delta_24h));
    });
  }

  /* ---------- Heatmap ---------- */
  function initHeatmap(data) {
    const max = Math.max(...data.cells.map((c) => c.value));
    const byDay = {};
    data.cells.forEach((c) => {
      (byDay[c.day] = byDay[c.day] || []).push(c);
    });

    const container = document.getElementById("heatmap");
    let html = "";
    data.days.forEach((day, di) => {
      const cells = (byDay[di] || []).sort((a, b) => a.hour - b.hour);
      html += `<div class="heatmap-row"><span class="heatmap-label">${day}</span>`;
      cells.forEach((c) => {
        const t = c.value / max;
        const bg =
          t < 0.05
            ? "rgba(255,255,255,0.03)"
            : `rgba(245,158,11,${(0.12 + t * 0.88).toFixed(3)})`;
        html += `<span class="heatmap-cell" style="background:${bg}" title="${day} ${String(
          c.hour
        ).padStart(2, "0")}:00 — ${c.value}"></span>`;
      });
      html += "</div>";
    });
    // Hour axis labels (every 4h).
    let axis = '<div class="heatmap-axis">';
    for (let h = 0; h < 24; h++) axis += `<span>${h % 4 === 0 ? h : ""}</span>`;
    axis += "</div>";
    container.innerHTML = html + axis;
  }

  /* ---------- Logs table ---------- */
  const LOGS_PAGE_SIZE = 100;
  let logsOffset = 0;
  const logsFilters = { search: "", source: "" };

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderLogsTable(data) {
    const body = document.getElementById("logs-table-body");
    const meta = document.getElementById("logs-table-meta");
    const prevBtn = document.getElementById("logs-prev");
    const nextBtn = document.getElementById("logs-next");
    if (!body) return;

    const { items, total, limit, offset } = data;
    logsOffset = offset;

    if (!items.length) {
      body.innerHTML =
        '<tr><td colspan="8" class="logs-table-empty">No logs in this time range</td></tr>';
    } else {
      body.innerHTML = items
        .map(
          (row) =>
            "<tr>" +
            `<td class="col-time">${escapeHtml(row.timestamp)}</td>` +
            `<td class="col-ip">${escapeHtml(row.ip)}</td>` +
            `<td class="col-country">${escapeHtml(row.flag)} ${escapeHtml(row.country)}</td>` +
            `<td class="col-type">${escapeHtml(row.type)}</td>` +
            `<td class="col-user" title="${escapeHtml(row.username)}">${escapeHtml(row.username)}</td>` +
            `<td class="col-pass" title="${escapeHtml(row.password)}">${escapeHtml(row.password)}</td>` +
            `<td>${row.port != null ? escapeHtml(row.port) : "—"}</td>` +
            `<td>${escapeHtml(row.source)}</td>` +
            "</tr>"
        )
        .join("");
    }

    if (meta) {
      const from = total ? offset + 1 : 0;
      const to = Math.min(offset + limit, total);
      meta.textContent = `${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()}`;
    }
    if (prevBtn) prevBtn.disabled = offset <= 0;
    if (nextBtn) nextBtn.disabled = offset + limit >= total;
  }

  function loadLogsTable(offset) {
    let url =
      `${apiUrl("/api/logs")}&limit=${LOGS_PAGE_SIZE}&offset=${offset}`;
    if (logsFilters.search) {
      url += `&search=${encodeURIComponent(logsFilters.search)}`;
    }
    if (logsFilters.source) {
      url += `&source=${encodeURIComponent(logsFilters.source)}`;
    }
    return getJSON(url).then(renderLogsTable).catch(() => {
      const body = document.getElementById("logs-table-body");
      if (body) {
        body.innerHTML =
          '<tr><td colspan="8" class="logs-table-empty">Failed to load logs</td></tr>';
      }
    });
  }

  function debounce(fn, wait) {
    let t;
    return function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  function initLogsTable() {
    const prevBtn = document.getElementById("logs-prev");
    const nextBtn = document.getElementById("logs-next");
    const searchEl = document.getElementById("logs-search");
    const sourceEl = document.getElementById("logs-source");
    if (!document.getElementById("logs-table-body")) return;

    loadLogsTable(0);

    if (prevBtn) {
      prevBtn.addEventListener("click", () => {
        if (logsOffset > 0) loadLogsTable(Math.max(0, logsOffset - LOGS_PAGE_SIZE));
      });
    }
    if (nextBtn) {
      nextBtn.addEventListener("click", () => {
        loadLogsTable(logsOffset + LOGS_PAGE_SIZE);
      });
    }
    if (searchEl) {
      searchEl.addEventListener(
        "input",
        debounce(() => {
          logsFilters.search = searchEl.value.trim();
          loadLogsTable(0); // reset to first page on new query
        }, 350)
      );
    }
    if (sourceEl) {
      sourceEl.addEventListener("change", () => {
        logsFilters.source = sourceEl.value;
        loadLogsTable(0);
      });
    }
  }

  /* ---------- Boot ---------- */
  function fetchAllData() {
    getJSON(apiUrl("/api/summary")).then(updateKpis).catch(() => {});
    getJSON(apiUrl("/api/geo")).then(initMap).catch(() => {});
    getJSON(apiUrl("/api/timeline")).then(initTimeline).catch(() => {});
    getJSON(apiUrl("/api/top-usernames"))
      .then((d) => horizontalBars("usernames-chart", d, COLORS.accent))
      .catch(() => {});
    getJSON(apiUrl("/api/top-passwords"))
      .then((d) => horizontalBars("passwords-chart", d, COLORS.red))
      .catch(() => {});
    getJSON(apiUrl("/api/event-types")).then(initDonut).catch(() => {});
    getJSON(apiUrl("/api/heatmap")).then(initHeatmap).catch(() => {});
  }

  function load() {
    applyChartDefaults();
    fetchAllData();
    initLogsTable();
  }

  function refreshData() {
    isRefreshing = true;
    fetchAllData();
    loadLogsTable(logsOffset); // keep current page + active filters
    isRefreshing = false;
  }

  /* ---------- Auto-refresh ---------- */
  const AUTO_INTERVAL_MS = 30000;
  let autoTimer = null;

  function initAutoRefresh() {
    const btn = document.getElementById("autorefresh-btn");
    const label = document.getElementById("autorefresh-label");
    if (!btn) return;

    const stored = localStorage.getItem("hw_autorefresh");
    let enabled = stored === null ? true : stored === "on";

    function apply() {
      btn.setAttribute("aria-pressed", enabled ? "true" : "false");
      if (label) label.textContent = enabled ? "Auto-refresh: on" : "Auto-refresh: off";
      if (autoTimer) {
        clearInterval(autoTimer);
        autoTimer = null;
      }
      if (enabled) {
        autoTimer = setInterval(refreshData, AUTO_INTERVAL_MS);
      }
    }

    btn.addEventListener("click", () => {
      enabled = !enabled;
      localStorage.setItem("hw_autorefresh", enabled ? "on" : "off");
      apply();
    });

    // Pause polling when the tab is hidden; resume when visible.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        if (autoTimer) {
          clearInterval(autoTimer);
          autoTimer = null;
        }
      } else if (enabled && !autoTimer) {
        refreshData();
        autoTimer = setInterval(refreshData, AUTO_INTERVAL_MS);
      }
    });

    apply();
  }

  function initSectionNav() {
    const links = document.querySelectorAll(".nav-item[data-section]");
    if (!links.length) return;

    const setActive = (key) => {
      links.forEach((link) => {
        link.classList.toggle("active", link.dataset.section === key);
      });
    };

    links.forEach((link) => {
      link.addEventListener("click", (e) => {
        const hash = link.getAttribute("href");
        if (!hash || !hash.startsWith("#")) return;
        const target = document.querySelector(hash);
        if (!target) return;
        e.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        const qs = window.location.search;
        history.replaceState(null, "", hash + qs);
        setActive(link.dataset.section);
      });
    });

    const sections = Array.from(links)
      .map((link) => {
        const el = document.querySelector(link.getAttribute("href"));
        return el ? { key: link.dataset.section, el } : null;
      })
      .filter(Boolean);

    if (sections.length && "IntersectionObserver" in window) {
      const observer = new IntersectionObserver(
        (entries) => {
          const visible = entries
            .filter((e) => e.isIntersecting)
            .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
          if (visible.length) {
            const hit = sections.find((s) => s.el === visible[0].target);
            if (hit) setActive(hit.key);
          }
        },
        { rootMargin: "-20% 0px -55% 0px", threshold: [0.1, 0.25, 0.5] }
      );
      sections.forEach((s) => observer.observe(s.el));
    }

    const hash = window.location.hash;
    if (hash) {
      const match = Array.from(links).find((l) => l.getAttribute("href") === hash);
      if (match) setActive(match.dataset.section);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    load();
    initSectionNav();
    initAutoRefresh();
  });

  const refresh = document.getElementById("refresh-btn");
  if (refresh) {
    refresh.addEventListener("click", () => refreshData());
  }
})();
