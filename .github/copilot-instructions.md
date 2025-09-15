# Copilot Instructions for AI Coding Agents

## Project Overview
This is a minimal Flask web application with SCSS/CSS styling and SQLAlchemy integration. The main entry point is `app.py`, which sets up the Flask app, configures SCSS, and provides a single homepage route (`/`).

## Key Files & Structure
- `app.py`: Main Flask app. Defines routes and runs the server with debug mode enabled.
- `requirements.txt`: Lists all Python dependencies. Use this for environment setup.
- `static/style.scss`: Source SCSS file for styling. Compiled to `static/style.css`.
- `static/style.css`: Compiled CSS. Linked in `index.html`.
- `templates/index.html`: Homepage template rendered by Flask.
- `env/`: Python virtual environment. Do not edit files here directly.

## Developer Workflows
- **Run the app:**
  ```bash
  flask run
  # or
  python app.py
  ```
- **Debug mode:** Enabled by default in `app.py` (`app.run(debug=True)`).
- **Install dependencies:**
  ```bash
  pip install -r requirements.txt
  ```
- **SCSS compilation:**
  - SCSS is compiled to CSS automatically via `Flask-Scss` when the app runs.
  - Edit `static/style.scss` for styles; do not edit `style.css` directly.

## Patterns & Conventions
- All routes are defined in `app.py`.
- Templates are stored in `templates/` and rendered using `render_template`.
- Static assets (CSS, SCSS) are in `static/`.
- Use the virtual environment in `env/` for all Python commands.
- SQLAlchemy is imported but not yet configured; add models and database setup in `app.py` if needed.

## Integration Points
- **Flask-Scss:** Handles SCSS compilation. No manual build step required.
- **Flask-SQLAlchemy:** Ready for database integration; currently unused.

## Examples
- To add a new route:
  ```python
  @app.route("/about")
  def about():
      return render_template('about.html')
  ```
- To add a new style:
  Edit `static/style.scss` and restart the app.

## Notes
- No custom build or test scripts detected.
- No database migrations or advanced workflows present.
- Minimal project; extend by adding routes, templates, and models as needed.

---
_If any section is unclear or missing, please provide feedback for improvement._
