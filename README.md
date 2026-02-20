# Cloud Security Management Dashboard

A Flask-based web application for cloud security management with user authentication.

## Features

- **Login and Authentication**
  - Admin login
  - User login
  - Password validation
  - Logout system

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python app.py
   ```

3. Open your browser and go to `http://127.0.0.1:5000/`

## Default Users

- **Admin**: username: `admin`, password: `admin123`
- **User**: username: `user`, password: `user123`

## Project Structure

- `app.py`: Main Flask application
- `models.py`: Database models
- `config.py`: Configuration settings
- `templates/`: HTML templates
- `static/`: CSS and static files
- `requirements.txt`: Python dependencies