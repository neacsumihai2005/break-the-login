from flask import Flask, jsonify, request, make_response
import psycopg2
import jwt
import datetime
import bcrypt
import uuid
import os
from functools import wraps
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

load_dotenv()

app = Flask(__name__)

# configurare baza de date
DB_HOST = "localhost"
DB_NAME = "authx_db"
DB_USER = "authx_user"
DB_PASS = os.getenv('DB_PASSWORD')

# cheie secreta pentru semnarea token-urilor JWT
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# memorie pentru rate limiting (se reseteaza la restartul serverului)
failed_attempts = {}
MAX_ATTEMPTS = 5

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def log_audit(user_id, action, resource="auth", ip_address=None):
    """Functie pentru salvarea evenimentelor in tabelul audit_logs"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (%s, %s, %s, %s)",
            (user_id, action, resource, ip_address)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[DEBUG] Eroare Audit Log: {e}")

def role_required(allowed_roles):
    """Decorator pentru verificarea rolului utilizatorului (RBAC)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.cookies.get('authx_session')
            if not token:
                return jsonify({"status": "error", "message": "Neautorizat."}), 401
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                if data.get('role') not in allowed_roles:
                    return jsonify({"status": "error", "message": "Acces interzis: permisiuni insuficiente."}), 403
                return f(data, *args, **kwargs)
            except Exception as e:
                return jsonify({"status": "error", "message": "Sesiune invalida."}), 401
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Date incomplete."}), 400
    
    email = data['email']
    password = data['password']
    
    # FIX 4.1: politica de parole (minim 8 caractere)
    if len(password) < 8:
        return jsonify({"status": "error", "message": "Parola trebuie sa aiba minim 8 caractere!"}), 400
        
    try:
        # FIX 4.2: stocare securizata cu Bcrypt (Hash + Salt)
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s) RETURNING id", 
            (email, hashed_password, 'USER') # default role
        )
        new_id = cur.fetchone()
        conn.commit()
        
        log_audit(new_id, "USER_REGISTERED", ip_address=request.remote_addr)
        
        cur.close()
        conn.close()
        return jsonify({"status": "success", "message": "Cont creat si securizat!"}), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({"status": "error", "message": "Eroare la crearea contului."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare interna."}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    ip = request.remote_addr

    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Lipsesc credentialele."}), 400

    email = data['email']
    password = data['password']

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # extragem si rolul utilizatorului
        cur.execute("SELECT id, password_hash, locked, role FROM users WHERE email = %s", (email,))
        row = cur.fetchone()

        error_msg = "Credentiale invalide."

        if row is None:
            log_audit(None, "LOGIN_FAIL_UNKNOWN_USER", ip_address=ip)
            return jsonify({"status": "error", "message": error_msg}), 401
        
        u_id, u_hash, u_locked, u_role = row

        # verificam daca este blocat (protectie Brute Force 4.3)
        if u_locked:
            log_audit(u_id, "LOGIN_ATTEMPT_LOCKED", ip_address=ip)
            return jsonify({"status": "error", "message": "Cont blocat."}), 403

        
        if not bcrypt.checkpw(password.encode('utf-8'), u_hash.encode('utf-8')):
            failed_attempts[email] = failed_attempts.get(email, 0) + 1
            log_audit(u_id, "LOGIN_FAIL_WRONG_PWD", ip_address=ip)
            
            if failed_attempts[email] >= MAX_ATTEMPTS:
                cur.execute("UPDATE users SET locked = TRUE WHERE id = %s", (u_id,))
                conn.commit()
                log_audit(u_id, "ACCOUNT_LOCKED", ip_address=ip)
                
            cur.close()
            conn.close()
            return jsonify({"status": "error", "message": error_msg}), 401
    
       
        failed_attempts[email] = 0
        log_audit(u_id, "LOGIN_SUCCESS", ip_address=ip)
        
        # cream token JWT care include rolul
        token = jwt.encode({
            'user_id': u_id,
            'role': u_role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        response = make_response(jsonify({"status": "success", "message": "Login reusit!", "role": u_role}))
        # cookie securizat (HttpOnly, SameSite)
        response.set_cookie('authx_session', token, httponly=True, samesite='Lax')
        
        cur.close()
        conn.close()
        return response, 200
        
    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare server."}), 500

@app.route('/tickets', methods=['GET'])
@role_required(['USER', 'MANAGER'])
def get_my_tickets(user_data):
    """utilizatorii vad doar tichetele lor,
    managerii vad tot in aceasta ruta sau in admin"""
    
    try:
        logged_user_id = user_data.get('user_id')
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # protectie IDOR (4.6): filtrare stricta dupa owner_id
        query = "SELECT id, title, description, status, severity FROM tickets WHERE owner_id = %s"
        cur.execute(query, (logged_user_id,))
        
        tickets = cur.fetchall()
        log_audit(logged_user_id, "VIEW_TICKETS", resource="tickets", ip_address=request.remote_addr)
        
        cur.close()
        conn.close()
        return jsonify({"status": "success", "data": tickets}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare server."}), 500

@app.route('/admin/tickets', methods=['GET'])
@role_required(['MANAGER'])
def get_all_tickets_admin(user_data):
    """endpoint exclusiv Manager: vizualizarea tuturor tichetelor din sistem"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM tickets") # fara filtrare owner_id
        tickets = cur.fetchall()
        
        log_audit(user_data.get('user_id'), "ADMIN_VIEW_ALL_TICKETS", resource="admin_tickets", ip_address=request.remote_addr)
        
        cur.close()
        conn.close()
        return jsonify({"status": "success", "data": tickets}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/audit', methods=['GET'])
@role_required(['MANAGER'])
def view_audit_logs(user_data):
    """endpoint exclusiv Manager: vizualizarea log-urilor de audit"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
        logs = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"status": "success", "audit_data": logs}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare server."}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """sterg cookie-ul si invalidez sesiunea"""
    response = make_response(jsonify({"status": "success", "message": "Delogare reusita."}))
    response.set_cookie('authx_session', '', expires=0, httponly=True)
    return response, 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """V2 Securizat: Generare token JWT scurt (15 minute) si prevenire User Enumeration"""
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"status": "error", "message": "Email necesar"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        # FIX: Prevenirea User Enumeration - Returnam acelasi mesaj si daca userul exista si daca nu
        generic_message = "Daca email-ul exista in sistem, a fost generat un link de resetare."
        
        reset_token = None
        if user:
            user_id = user
            # FIX: Generam un token JWT criptografic, valabil doar 15 minute
            reset_token = jwt.encode({
                'reset_user_id': user_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            log_audit(user_id, "PASSWORD_RESET_REQUESTED", ip_address=request.remote_addr)

        cur.close()
        conn.close()

        return jsonify({
            "status": "success",
            "message": generic_message,
            # [DEBUG/PoC]: In productie, token-ul se trimite pe email. Pentru demonstratie, il returnam in raspuns.
            "debug_token": reset_token
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare server."}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    """V2 Securizat: Validare stricta token si aplicare politica de parole"""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({"status": "error", "message": "Token-ul si noua parola sunt obligatorii."}), 400

    # FIX: Se aplica din nou politica de complexitate de la register
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Noua parola trebuie sa aiba minim 8 caractere!"}), 400

    try:
        # 1. Validam ca token-ul este corect si nu a expirat
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded.get('reset_user_id')

        # 2. Hash-uim noua parola cu Bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()

        # 3. Updatam parola. Optional: Deblocam contul daca a fost victima unui brute force
        cur.execute(
            "UPDATE users SET password_hash = %s, locked = FALSE WHERE id = %s", 
            (hashed_password, user_id)
        )
        conn.commit()

        if cur.rowcount == 0:
            return jsonify({"status": "error", "message": "Eroare la resetare."}), 404
        
        log_audit(user_id, "PASSWORD_RESET_SUCCESS", ip_address=request.remote_addr)

        cur.close()
        conn.close()
        return jsonify({"status": "success", "message": "Parola a fost schimbata si contul deblocat!"}), 200

    except jwt.ExpiredSignatureError:
        # FIX: Token-urile vechi nu mai pot fi folosite
        return jsonify({"status": "error", "message": "Token-ul a expirat (limita de 15 minute)."}), 401
    except jwt.InvalidTokenError:
        # FIX: Protectie impotriva token-urilor modificate manual (Criptografie)
        return jsonify({"status": "error", "message": "Token invalid sau manipulat."}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare server."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
