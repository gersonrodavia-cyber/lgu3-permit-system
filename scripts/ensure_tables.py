import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import db, app

with app.app_context():
    db.create_all()
    print('db.create_all() executed — tables created (if missing)')
