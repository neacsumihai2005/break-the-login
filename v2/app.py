from flask import Flask, jsonify, request, make_response
import psycopg2
import jwt
import datetime
import bcrypt
import uuid
import os
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
    """Functie pentru salvarea evenimentelor in tabelul audit_logs """
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
            (email, hashed_password, 'USER')
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
        
        # extragem datele utilizatorului
        cur.execute("SELECT id, password_hash, locked FROM users WHERE email = %s", (email,))
        row = cur.fetchone()

        #print(f"[DEBUG DB] Rand gasit pentru {email}: {row}")

        error_msg = "Credentiale invalide."

        if row is None:
            log_audit(None, "LOGIN_FAIL_UNKNOWN_USER", ip_address=ip)
            return jsonify({"status": "error", "message": error_msg}), 401
        
        # unpacking
        # row este (id, password_hash, locked)
        u_id, u_hash, u_locked = row

        # verificam daca este blocat
        if u_locked:
            log_audit(u_id, "LOGIN_ATTEMPT_LOCKED", ip_address=ip)
            return jsonify({"status": "error", "message": "Cont blocat."}), 403

        # verificare parola
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
    
        # resetare succes
        failed_attempts[email] = 0
        log_audit(u_id, "LOGIN_SUCCESS", ip_address=ip)
        
        token = jwt.encode({
            'user_id': u_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        response = make_response(jsonify({"status": "success", "message": "Login reusit!"}))
        response.set_cookie('authx_session', token, httponly=True, samesite='Lax')
        
        cur.close()
        conn.close()
        return response, 200
        
    except Exception as e:
        print(f"--- EROARE CRITICA LOGIN: {e} ---")
        return jsonify({"status": "error", "message": "Eroare server."}), 500
        

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    # FIX 4.4: raspuns uniform pentru a preveni enumerarea 
    msg = "Daca adresa exista, un token de resetare a fost trimis."
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if user:
        # FIX 4.6: token impredictibil (UUID v4) 
        token = str(uuid.uuid4())
        log_audit(user, "PWD_RESET_TOKEN_GEN", ip_address=request.remote_addr)
        cur.close()
        conn.close()
        return jsonify({"status": "success", "message": msg, "debug_token": token}), 200
    
    cur.close()
    conn.close()
    return jsonify({"status": "success", "message": msg}), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    token = data.get('token')
    new_pwd = data.get('new_password')

    if not email or not token or not new_pwd or len(new_pwd) < 8:
        return jsonify({"status": "error", "message": "Date invalide sau parola prea scurta."}), 400

    try:
        hashed = bcrypt.hashpw(new_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s RETURNING id", (hashed, email))
        user = cur.fetchone()
        
        if user:
            conn.commit()
            log_audit(user, "PWD_RESET_SUCCESS", ip_address=request.remote_addr)
            cur.close()
            conn.close()
            return jsonify({"status": "success", "message": "Parola a fost actualizata!"})
        
        cur.close()
        conn.close()
        return jsonify({"status": "error", "message": "Eroare resetare."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": "Eroare server."}), 500

@app.route('/logout', methods=['POST'])
def logout():
    # FIX 4.5: invalidarea sesiunii prin stergerea cookie-ului 
    response = make_response(jsonify({"status": "success", "message": "Delogare reusita."}))
    response.set_cookie('authx_session', '', expires=0, httponly=True)
    return response, 200
    
@app.route('/tickets', methods=['GET'])
def get_my_tickets():
    token = request.cookies.get('authx_session')
    if not token:
        return jsonify({"status": "error", "message": "Neautorizat."}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # ne asiguram ca luam ID-ul corect din JWT
        logged_user_id = data.get('user_id')
        if isinstance(logged_user_id, (list, tuple)):
            logged_user_id = logged_user_id

        conn = get_db_connection()
        # folosim RealDictCursor pentru mapare automata
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = "SELECT id, title, description, status, severity FROM tickets WHERE owner_id = %s"
        cur.execute(query, (logged_user_id,))
        
        tickets = cur.fetchall()
        
        log_audit(logged_user_id, "VIEW_TICKETS", resource="tickets", ip_address=request.remote_addr)
        
        cur.close()
        conn.close()

        # trimitem direct 'tickets' in JSON
        return jsonify({"status": "success", "data": tickets}), 200

    except Exception as e:
        print(f"--- EROARE FINALA TICKETS: {e} ---")
        return jsonify({"status": "error", "message": "Eroare server."}), 500
                
if __name__ == '__main__':
    app.run(debug=True, port=5000)
