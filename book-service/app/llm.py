"""
llm.py – Asynchronous LLM call (Gemini) for book summaries.
The background thread updates the books.summary column once the response
arrives; it does NOT block the POST /books response.
"""
import threading
import logging
import google.generativeai as genai
from app import config

logger = logging.getLogger(__name__)


def _fetch_and_store_summary(isbn: str, title: str, author: str) -> None:
    """
    Called in a daemon thread:
    1. Ask Gemini for a 500-word summary.
    2. UPDATE books SET summary = ... WHERE ISBN = isbn.
    Errors are logged but never re-raised (we must not crash the thread).
    """
    try:
        if not config.GEMINI_API_KEY:
            logger.warning("GEMINI_API_KEY not set; skipping LLM call for ISBN=%s", isbn)
            return

        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.5-flash-lite")
        prompt = (
            f"Write a 500-word summary of the book titled '{title}' by {author}. "
            "Include key themes, target audience, and why it is significant."
        )
        response = model.generate_content(prompt)
        summary = response.text

        # Import here to avoid circular imports at module load time
        from app.db import get_connection
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE books SET summary = %s WHERE ISBN = %s",
                (summary, isbn),
            )
            conn.commit()
            cursor.close()
        logger.info("Summary stored for ISBN=%s", isbn)

    except Exception:
        logger.exception("LLM summary fetch failed for ISBN=%s", isbn)


def trigger_summary(isbn: str, title: str, author: str) -> None:
    """Fire-and-forget: start a daemon thread to fetch + store the summary."""
    t = threading.Thread(
        target=_fetch_and_store_summary,
        args=(isbn, title, author),
        daemon=True,
    )
    t.start()
