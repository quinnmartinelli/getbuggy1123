FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Installs Chromium plus the OS-level libraries it needs to actually run
# (fonts, graphics libs, etc.) — "--with-deps" is what makes this work on a
# bare slim image instead of Playwright's own preloaded image.
RUN playwright install --with-deps chromium

COPY . .

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
