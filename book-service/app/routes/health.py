"""
routes/health.py – Simple liveness endpoint.
GET /status → 200 OK (text/plain)
"""
from flask import Blueprint, Response

health_bp = Blueprint("health", __name__)


@health_bp.get("/status")
def status():
    return Response("OK", status=200, mimetype="text/plain")
