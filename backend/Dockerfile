# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /code

# Copy the requirements file into the container at /code
COPY ./requirements.txt /code/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install torch --extra-index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy all the backend files into the container
# This is simpler and will now include main.py at the root
# Copy the entire 'app' directory, config, etc.
COPY . /code/

# --- COMMAND UPDATED ---
# Uvicorn now looks for the 'app' object inside the 'main.py' file.
# The previous path was 'app.main:app'.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--timeout-keep-alive", "120"]