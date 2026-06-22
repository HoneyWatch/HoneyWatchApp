"""HoneyWatch analytics dashboard (Flask).

Serves the overview page and JSON API endpoints backed by ``honeywatch.db``.
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from . import db

app = Flask(__name__)


def _range() -> str:
    return db.normalize_range(request.args.get("range"))


@app.context_processor
def _template_globals():
    range_key = _range()
    return {
        "time_range": range_key,
        "range_delta_label": db.range_delta_label(range_key),
    }


@app.route("/")
def overview():
    range_key = _range()
    return render_template(
        "overview.html",
        summary=db.get_summary(period=range_key),
        top_countries=db.get_top_countries(period=range_key),
        recent=db.get_recent(period=range_key),
        log_sources=db.get_log_sources(),
        active_page="overview",
    )


@app.route("/api/summary")
def api_summary():
    return jsonify(db.get_summary(period=_range()))


@app.route("/api/countries")
def api_countries():
    return jsonify(db.get_top_countries(period=_range()))


@app.route("/api/geo")
def api_geo():
    return jsonify(db.get_geo(period=_range()))


@app.route("/api/timeline")
def api_timeline():
    return jsonify(db.get_timeline(period=_range()))


@app.route("/api/event-types")
def api_event_types():
    return jsonify(db.get_event_types(period=_range()))


@app.route("/api/top-usernames")
def api_top_usernames():
    return jsonify(db.get_top_usernames(period=_range()))


@app.route("/api/top-passwords")
def api_top_passwords():
    return jsonify(db.get_top_passwords(period=_range()))


@app.route("/api/heatmap")
def api_heatmap():
    return jsonify(db.get_heatmap(period=_range()))


@app.route("/api/recent")
def api_recent():
    return jsonify(db.get_recent(period=_range()))


@app.route("/api/logs")
def api_logs():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = (request.args.get("search") or "").strip()
    source = (request.args.get("source") or "").strip()
    return jsonify(
        db.get_logs(
            period=_range(),
            limit=limit,
            offset=offset,
            search=search,
            source=source,
        )
    )


def main() -> None:
    import os

    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    main()
