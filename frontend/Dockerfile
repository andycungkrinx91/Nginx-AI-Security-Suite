FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY ./requirements.txt /app/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

# Copy the main app and the theme configuration
COPY ./Home.py /app/Home.py
COPY ./.streamlit /app/.streamlit

# --- ADD THIS LINE ---
# Copy the new pages directory for the multi-page app
COPY ./pages /app/pages

# Expose the port Streamlit runs on
EXPOSE 5000

# --- UPDATED COMMAND ---
# Command to run the new main script
CMD ["streamlit", "run", "Home.py", "--server.port=5000", "--server.address=0.0.0.0"]