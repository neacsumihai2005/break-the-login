from flask import Flask, jsonify, request, make_response
import psycopg2
import jwt
import datetime

app = Flask(__name__)

# configuratia bazei de date
DB_HOST = "localhost"
DB_NAME = "authx_db"
DB_USER = "authx_user"
DB_PASS = "123"  # INSEREAZA PAROLA TA AICI

#o cheie se creta slaba
app.config['SECRET_KEY'] = 'secret123'

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

@app.route('/ticket', methods=['POST'])
def create_ticket():
    """Endpoint vulnerabil: permite crearea unui tichet pentru user-ul logat"""
    token = request.cookies.get('authx_session')
    if not token:
        return jsonify({"status": "error", "message": "Logati-va intai"}), 401

    try:
        # Decodam token-ul si luam ID-ul
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        owner_id = data['user_id']
        
        req_data = request.get_json()
        title = req_data.get('title')
        description = req_data.get('description')
        severity = req_data.get('severity', 'LOW')
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tickets (title, description, severity, owner_id) VALUES (%s, %s, %s, %s) RETURNING id",
            (title, description, severity, owner_id)
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({"status": "success", "ticket_id": new_id}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tickets/all', methods=['GET'])
def get_all_tickets_vulnerable():
    """Returneaza toate tichetele din sistem oricui e logat"""
    token = request.cookies.get('authx_session')
    if not token:
        return jsonify({"status": "error", "message": "Neautorizat"}), 401
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # nu filtram deloc dupa owner_id
        cur.execute("SELECT * FROM tickets")
        tickets = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"status": "success", "all_system_data": tickets}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/ticket/<int:ticket_id>', methods=['GET'])
def get_ticket_by_id_idor(ticket_id):
    """Poti vedea orice tichet doar schimband ID-ul in URL"""
    token = request.cookies.get('authx_session')
    if not token:
        return jsonify({"status": "error", "message": "Logati-va intai"}), 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # luam tichetul doar dupa ID-ul din URL 
        # nu verificam daca owner_id din tabel corespunde cu user_id din token
        cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if ticket:
            return jsonify({"status": "success", "ticket_data": ticket}), 200
        return jsonify({"status": "error", "message": "Nu exista"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    print("\n--- [DEBUG] START REQUEST REGISTER ---")
    data = request.get_json()
    print(f"[DEBUG] Date primite de la utilizator: {data}")
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Date incomplete."}), 400
    
    email = data['email']
    password = data['password']
    role = 'USER' 

    try:
        print("[DEBUG] Ma conectez la DB...")
        conn = get_db_connection()
        cur = conn.cursor()
        
        insert_query = "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)"
        
        print("[DEBUG] Execut query-ul...")
        cur.execute(insert_query, (email, password, role))
        
        print(f"[DEBUG] Randuri afectate in memorie: {cur.rowcount}")
        
        conn.commit()
        print("[DEBUG] COMMIT executat cu succes pe baza de date!")
        
        cur.close()
        conn.close()
        
        return jsonify({"status": "success", "message": "Cont creat cu succes!"}), 201

    except Exception as e:
        print(f"[DEBUG] !!! EROARE CRITICA !!! : {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Email-ul si parola sunt obligatorii."}), 400

    email = data['email']
    password = data['password']

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # cautam utilizatorul in baza de date
        cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return jsonify({"status": "error", "message": "Utilizatorul nu exista!"}), 404
        
        # verificam parola
        stored_password = user[1]

        if password != stored_password:
            cur.close()
            conn.close()
            return jsonify({"status": "error", "message": "Parola incorecta!"}), 401
    
        # daca ajungem aici, parola e corecta
        
        # cream o sesiune vulnerabila

        #1. cream un token JWT care expira peste 10 ani
        token = jwt.encode({
            'user_id': user[0],
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        #2. pregatim raspunsul de succes
        response = make_response(jsonify({"status": "success", "message": "login reusit!"}))

        #3. setam token-ul intr-un cookie vulnerabil (fara HttpOnly, fara Secure)
        response.set_cookie('authx_session', token)

        
        cur.close()
        conn.close()
        return response, 200
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"status": "error", "message": "Email necesar"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user:
        return jsonify({"status": "error", "message": "Utilizator existent."}), 404
    
    predictable_token = f"reset-{email}"

    cur.close()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Token de resetare generat.",
        "debug_token": predictable_token
    }), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({"status": "error", "message": "Token invalid."}), 403
    
    email = token.replace("reset-", "")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (new_password, email))
        conn.commit()

        if cur.rowcount == 0:
            return jsonify({"status": "error", "message": "Eroare la resetare"}), 404
        
        cur.close()
        conn.close()
        return jsonify({"status": "success", "message": "Parola a fost schimbata!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    # stergem cookie-ul doar din browser.
    # backend-ul nu invalideaza token-ul JWT (nu avem blacklist). in fine, nici la v2 n-avem dar tot e secure pt ca expira intr-o ora si e greu de furat din start pt ca avem HttpOnly = True acolo
    # daca a fost furat, va fi valid inca 10 ani!
    response = make_response(jsonify({"status": "success", "message": "Delogare realizata local."}))
    
    # suprascriem cookie-ul cu unul gol care expira instant
    response.set_cookie('authx_session', '', expires=0)
    
    return response, 200
    
    

if __name__ == '__main__':
    app.run(debug=True, port=5000)
