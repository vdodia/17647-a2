"""
main.py – Flask application factory and entry point.
"""
import logging
from flask import Flask


from app.routes.customers import customers_bp
from app.routes.health import health_bp
from app.db import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def create_app() -> Flask:
    app = Flask(__name__)

    # Initialize DB schema before serving traffc
    init_db()

    app.register_blueprint(health_bp)

    app.register_blueprint(customers_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
