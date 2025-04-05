# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install Pipenv
RUN pip install pipenv

# Copy Pipenv files and install dependencies
COPY Pipfile Pipfile.lock ./
RUN pipenv install --deploy --ignore-pipfile

# Copy the rest of the application code
COPY . .

# Expose port 8000 (adjust if needed)
EXPOSE 8000

# Command to run the FastAPI app with Uvicorn
CMD ["pipenv", "run", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
