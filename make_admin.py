import sys
from server import app, db, User

def make_admin(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"Error: User '{username}' not found.")
            return
        
        if user.is_admin:
            print(f"User '{username}' is already an admin.")
            return
            
        user.is_admin = True
        db.session.commit()
        print(f"Success: User '{username}' is now an admin.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    make_admin(username)
