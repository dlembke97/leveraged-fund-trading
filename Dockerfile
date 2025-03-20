# Use an official Python runtime as a base image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Install pipenv
RUN pip install pipenv

# Copy Pipfile and Pipfile.lock
COPY Pipfile Pipfile.lock ./

# Install dependencies using Pipenv
RUN pipenv install --deploy --ignore-pipfile

# Copy the rest of the application
COPY . .

# Set the working directory to where main.py is located
WORKDIR /app/scripts

# Run the bot
CMD ["pipenv", "run", "python", "main.py"]
