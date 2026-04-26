import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

# exact ca in app.py
DB_HOST = "localhost"
DB_NAME = "authx_db"
DB_USER = "authx_user"
DB_PASS = os.getenv('DB_PASSWORD') 

def init_database():
    conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
    cur = conn.cursor()

    # 1. stergem tabelele vechi (daca exista) pentru a face curat
    print("Sterg tabelele vechi...")
    cur.execute("DROP TABLE IF EXISTS audit_logs CASCADE;")
    cur.execute("DROP TABLE IF EXISTS tickets CASCADE;")
    cur.execute("DROP TABLE IF EXISTS users CASCADE;")

    # 2. cream tabelul USERS
    print("Creez tabelul users...")
    cur.execute("""
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'USER',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locked BOOLEAN DEFAULT FALSE
        );
    """)

    # 3. cream tabelul TICKETS 
    print("Creez tabelul tickets...")
    cur.execute("""
        CREATE TABLE tickets (
            id SERIAL PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            severity VARCHAR(50),
            status VARCHAR(50) DEFAULT 'OPEN',
            owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # 4. cream tabelul AUDIT_LOGS 
    print("Creez tabelul audit_logs...")
    cur.execute("""
        CREATE TABLE audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(255) NOT NULL,
            resource VARCHAR(255),
            resource_id VARCHAR(255),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45)
        );
    """)

    # salvam modificarile si inchidem
    conn.commit()
    cur.close()
    conn.close()
    print("Baza de date a fost initializata cu succes!")

if __name__ == '__main__':
    init_database()
