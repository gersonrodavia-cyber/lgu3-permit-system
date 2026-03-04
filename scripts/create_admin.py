from app import app, db, User
import bcrypt

ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = 'adminpass'

with app.app_context():
    existing = User.query.filter_by(email=ADMIN_EMAIL).first()
    if existing:
        print(f"Admin already exists: {ADMIN_EMAIL} (id={existing.id})")
    else:
        hashed = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
        admin = User(
            username='admin',
            email=ADMIN_EMAIL,
            first_name='Admin',
            last_name='User',
            business_name='LGU Admin',
            password=hashed,
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Created admin user: {ADMIN_EMAIL} with password '{ADMIN_PASSWORD}'")
