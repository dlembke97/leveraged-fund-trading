# Use the Python 3.11 slim image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the Pipfile and Pipfile.lock to install dependencies
COPY Pipfile Pipfile.lock /app/

# Install pipenv and dependencies from the Pipfile
RUN pip install --no-cache-dir pipenv \
    && pipenv install --deploy --ignore-pipfile

# Copy the rest of the application code
COPY . /app/

# Expose the port the app runs on
EXPOSE 8000

# Use pipenv to run the FastAPI app with Uvicorn
CMD ["pipenv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
