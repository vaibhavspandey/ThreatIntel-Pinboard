FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

# Run Watchlist.py directly (no pages structure needed)
CMD ["streamlit", "run", "Watchlist.py", "--server.port=8501", "--server.address=0.0.0.0"]
