"""
routes/books.py – Books CRUD endpoints.

Endpoints:
    POST   /books
    PUT    /books/<ISBN>
    GET    /books/<ISBN>
    GET    /books/isbn/<ISBN>
"""
import logging
from flask import Blueprint, request, jsonify
import mysql.connector

from app.db import get_connection
from app.validation import validate_price, check_required_fields
from app.llm import trigger_summary

logger = logging.getLogger(__name__)

books_bp = Blueprint("books", __name__)

BOOK_FIELDS = ["ISBN", "title", "Author", "description", "genre", "price", "quantity"]


def _row_to_dict(row: tuple, include_summary: bool = False) -> dict:
    """Convert a DB row to API response dict."""
    book = {
        "ISBN":        row[0],
        "title":       row[1],
        "Author":      row[2],
        "description": row[3],
        "genre":       row[4],
        "price":       float(row[5]),
        "quantity":    row[6],
    }
    if include_summary:
        book["summary"] = row[7]
    return book


def _validate_book_payload(data: dict) -> str | None:
    """
    Return an error message string if invalid, else None.
    Validates: all fields present, price format.
    Does NOT validate ISBN per assignment spec.
    """
    missing = check_required_fields(data, BOOK_FIELDS)
    if missing:
        return f"Missing required fields: {', '.join(missing)}"
    if not validate_price(data["price"]):
        return "price must be a valid number with 0-2 decimal places"
    return None


# ---------------------------------------------------------------------------
# POST /books
# ---------------------------------------------------------------------------
@books_bp.post("/books")
def add_book():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    error = _validate_book_payload(data)
    if error:
        return jsonify({"message": error}), 400

    isbn     = data["ISBN"]
    title    = data["title"]
    author   = data["Author"]
    desc     = data["description"]
    genre    = data["genre"]
    price    = data["price"]
    quantity = data["quantity"]

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO books (ISBN, title, Author, description, genre, price, quantity)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (isbn, title, author, desc, genre, price, quantity),
            )
            conn.commit()
            cursor.close()
    except mysql.connector.IntegrityError:
        return jsonify({"message": "This ISBN already exists in the system."}), 422
    except Exception:
        logger.exception("DB error on POST /books")
        return jsonify({"message": "Internal server error"}), 500

    # Fire-and-forget LLM summary (does not block response)
    trigger_summary(isbn, title, author)

    response_body = {
        "ISBN":        isbn,
        "title":       title,
        "Author":      author,
        "description": desc,
        "genre":       genre,
        "price":       float(price),
        "quantity":    quantity,
    }
    location = request.host_url.rstrip("/") + f"/books/{isbn}"
    response = jsonify(response_body)
    response.status_code = 201
    response.headers["Location"] = location
    return response


# ---------------------------------------------------------------------------
# PUT /books/<ISBN>
# ---------------------------------------------------------------------------
@books_bp.put("/books/<string:isbn>")
def update_book(isbn: str):
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    error = _validate_book_payload(data)
    if error:
        return jsonify({"message": error}), 400

    if data["ISBN"] != isbn:
        return jsonify({"message": "ISBN mismatch between URL and payload"}), 400

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ISBN FROM books WHERE ISBN = %s", (isbn,))
            if cursor.fetchone() is None:
                cursor.close()
                return jsonify({"message": "ISBN not found"}), 404

            cursor.execute(
                """
                UPDATE books
                SET title=%s, Author=%s, description=%s, genre=%s, price=%s, quantity=%s
                WHERE ISBN=%s
                """,
                (
                    data["title"], data["Author"], data["description"],
                    data["genre"], data["price"], data["quantity"], isbn,
                ),
            )
            conn.commit()
            cursor.close()
    except Exception:
        logger.exception("DB error on PUT /books/%s", isbn)
        return jsonify({"message": "Internal server error"}), 500

    response_body = {
        "ISBN":        isbn,
        "title":       data["title"],
        "Author":      data["Author"],
        "description": data["description"],
        "genre":       data["genre"],
        "price":       float(data["price"]),
        "quantity":    data["quantity"],
    }
    return jsonify(response_body), 200


# ---------------------------------------------------------------------------
# GET /books/<ISBN>  and  GET /books/isbn/<ISBN>
# ---------------------------------------------------------------------------
def _get_book_by_isbn(isbn: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ISBN, title, Author, description, genre, price, quantity, summary "
                "FROM books WHERE ISBN = %s",
                (isbn,),
            )
            row = cursor.fetchone()
            cursor.close()
    except Exception:
        logger.exception("DB error on GET /books/%s", isbn)
        return jsonify({"message": "Internal server error"}), 500

    if row is None:
        return jsonify({"message": "ISBN not found"}), 404

    return jsonify(_row_to_dict(row, include_summary=True)), 200


@books_bp.get("/books/<string:isbn>")
def get_book(isbn: str):
    return _get_book_by_isbn(isbn)


@books_bp.get("/books/isbn/<string:isbn>")
def get_book_by_isbn_path(isbn: str):
    return _get_book_by_isbn(isbn)
