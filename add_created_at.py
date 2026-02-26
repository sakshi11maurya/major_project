# add_created_at.py

from app import db  # Make sure this imports your Flask app's db object
from datetime import datetime

# Add the 'created_at' column if it doesn't exist
try:
    db.engine.execute('ALTER TABLE alert ADD COLUMN created_at DATETIME')
    print("✅ Column 'created_at' added successfully!")
except Exception as e:
    print("⚠ Could not add column:", e)

# Optional: backfill existing rows with the current timestamp so there are no NULLs
try:
    db.engine.execute(
        "UPDATE alert SET created_at = ? WHERE created_at IS NULL",
        (datetime.utcnow(),)
    )
    print("✅ Existing rows backfilled with current timestamp!")
except Exception as e:
    print("⚠ Could not backfill existing rows:", e)