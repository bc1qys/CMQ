from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import secrets
import logging

app = Flask(__name__)

# Configure logging to debug database issues
logging.basicConfig(level=logging.DEBUG)

# Initialize the SQLite database
def init_db():
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        app.logger.debug("Creating database tables...")
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT,
                     preferred_role TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS teams (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT UNIQUE,
                     password TEXT,
                     role TEXT,
                     score INTEGER DEFAULT 0,
                     creator_id INTEGER
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_teams (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     team_id INTEGER,
                     UNIQUE(user_id, team_id)
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS challenges (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT,
                     flag TEXT,
                     points INTEGER,
                     level TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS matches (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     challenge_id INTEGER,
                     vm_id TEXT,
                     ip_address TEXT,
                     status TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS team_matches (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     team_id INTEGER,
                     match_id INTEGER,
                     access_token TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS defenses (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     team_id INTEGER,
                     challenge_id INTEGER,
                     proof TEXT
                     )''')
        conn.commit()
        app.logger.debug("Database tables created successfully")
    except sqlite3.Error as e:
        app.logger.error(f"Database initialization failed: {e}")
    finally:
        conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    preferred_role = data.get('preferred_role')
    
    if not username or not password or preferred_role not in ['attaque', 'defense', '']:
        return jsonify({"message": "Données invalides"}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, preferred_role) VALUES (?, ?, ?)",
                  (username, hashed_password, preferred_role or None))
        conn.commit()
        return jsonify({"message": "Compte utilisateur créé"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Nom d'utilisateur déjà pris"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in register_user: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, password, preferred_role FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        
        if result and bcrypt.checkpw(password.encode('utf-8'), result[1]):
            return jsonify({
                "message": "Connexion réussie",
                "user_id": result[0],
                "preferred_role": result[2]
            })
        else:
            return jsonify({"message": "Nom ou mot de passe incorrect"}), 401
    except sqlite3.Error as e:
        app.logger.error(f"Error in login_user: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/join_team', methods=['POST'])
def join_team():
    data = request.get_json()
    user_id = data.get('user_id')
    team_id = data.get('team_id')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        c.execute("SELECT id, role FROM teams WHERE id = ?", (team_id,))
        team = c.fetchone()
        
        if not user or not team:
            return jsonify({"message": "Utilisateur ou équipe invalide"}), 400
        
        c.execute("SELECT id FROM user_teams WHERE user_id = ?", (user_id,))
        if c.fetchone():
            return jsonify({"message": "Vous êtes déjà dans une équipe"}), 400
        
        c.execute("INSERT INTO user_teams (user_id, team_id) VALUES (?, ?)", (user_id, team_id))
        conn.commit()
        return jsonify({"message": "Équipe rejointe avec succès"})
    except sqlite3.Error as e:
        app.logger.error(f"Error in join_team: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/leave_team', methods=['POST'])
def leave_team():
    data = request.get_json()
    user_id = data.get('user_id')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM user_teams WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if result:
            c.execute("DELETE FROM user_teams WHERE user_id = ?", (user_id,))
            conn.commit()
            return jsonify({"message": "Équipe quittée avec succès"})
        else:
            return jsonify({"message": "Vous n'êtes pas dans une équipe"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in leave_team: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    role = data.get('role')
    user_id = data.get('user_id')
    
    if not name or not password or role not in ['attaque', 'defense'] or not user_id:
        return jsonify({"message": "Données invalides"}), 400
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not c.fetchone():
            return jsonify({"message": "Utilisateur invalide"}), 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        c.execute("INSERT INTO teams (name, password, role, creator_id) VALUES (?, ?, ?, ?)",
                  (name, hashed_password, role, user_id))
        team_id = c.lastrowid
        c.execute("INSERT INTO user_teams (user_id, team_id) VALUES (?, ?)",
                  (user_id, team_id))
        conn.commit()
        return jsonify({"message": "Inscription réussie", "team_id": team_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Nom d'équipe déjà pris"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in register: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, password, role FROM teams WHERE name = ?", (name,))
        result = c.fetchone()
        
        if result and bcrypt.checkpw(password.encode('utf-8'), result[1]):
            return jsonify({
                "message": "Connexion réussie",
                "team_id": result[0],
                "role": result[2]
            })
        else:
            return jsonify({"message": "Nom ou mot de passe incorrect"}), 401
    except sqlite3.Error as e:
        app.logger.error(f"Error in login: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/join_match', methods=['POST'])
def join_match():
    data = request.get_json()
    team_id = data.get('team_id')
    match_id = data.get('match_id')
    user_id = data.get('user_id')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        team = c.fetchone()
        if not team:
            return jsonify({"message": "Équipe invalide"}), 400
        if team[0] != user_id:
            return jsonify({"message": "Seul le créateur de l'équipe peut rejoindre un match"}), 403
        
        c.execute("SELECT vm_id, ip_address FROM matches WHERE id = ? AND status = 'en cours'", (match_id,))
        match = c.fetchone()
        
        if match:
            vm_id, ip_address = match
            access_token = secrets.token_hex(16)
            c.execute("INSERT INTO team_matches (team_id, match_id, access_token) VALUES (?, ?, ?)",
                      (team_id, match_id, access_token))
            conn.commit()
            return jsonify({
                "message": "Match rejoint!",
                "vm_ip": ip_address,
                "access_token": access_token,
                "guacamole_url": f"http://192.168.1.100/guacamole?token={access_token}"
            })
        else:
            return jsonify({"message": "Match invalide ou terminé!"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in join_match: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/leave_match', methods=['POST'])
def leave_match():
    data = request.get_json()
    team_id = data.get('team_id')
    match_id = data.get('match_id')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM team_matches WHERE team_id = ? AND match_id = ?", (team_id, match_id))
        result = c.fetchone()
        
        if result:
            c.execute("DELETE FROM team_matches WHERE team_id = ? AND match_id = ?", (team_id, match_id))
            conn.commit()
            return jsonify({"message": "Match quitté avec succès"})
        else:
            return jsonify({"message": "Vous n'êtes pas dans ce match!"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in leave_match: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    data = request.get_json()
    team_id = data.get('team_id')
    flag = data.get('flag')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT role FROM teams WHERE id = ?", (team_id,))
        role = c.fetchone()
        if not role or role[0] != 'attaque':
            return jsonify({"message": "Seules les équipes attaque peuvent soumettre des flags"}), 403
        
        c.execute("SELECT id, points FROM challenges WHERE flag = ?", (flag,))
        result = c.fetchone()
        
        if result:
            challenge_id, points = result
            c.execute("SELECT id FROM team_matches WHERE team_id = ? AND match_id IN (SELECT id FROM matches WHERE challenge_id = ?)",
                      (team_id, challenge_id))
            if c.fetchone():
                c.execute("UPDATE teams SET score = score + ? WHERE id = ?", (points, team_id))
                conn.commit()
                return jsonify({"message": "Flag correct!", "points": points})
            else:
                return jsonify({"message": "Vous n'êtes pas inscrit à un match pour ce défi"}), 403
        else:
            return jsonify({"message": "Flag incorrect!"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in submit_flag: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/submit_defense', methods=['POST'])
def submit_defense():
    data = request.get_json()
    team_id = data.get('team_id')
    challenge_id = data.get('challenge_id')
    proof = data.get('proof')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT role FROM teams WHERE id = ?", (team_id,))
        role = c.fetchone()
        if not role or role[0] != 'defense':
            return jsonify({"message": "Seule l'équipe défense peut soumettre des preuves"}), 403
        
        c.execute("SELECT points FROM challenges WHERE id = ?", (challenge_id,))
        result = c.fetchone()
        
        if result:
            points = result[0]
            c.execute("INSERT INTO defenses (team_id, challenge_id, proof) VALUES (?, ?, ?)",
                      (team_id, challenge_id, proof))
            c.execute("UPDATE teams SET score = score + ? WHERE id = ?", (points, team_id))
            conn.commit()
            return jsonify({"message": "Preuve acceptée!", "points": points})
        else:
            return jsonify({"message": "Défi invalide!"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in submit_defense: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

@app.route('/teams', methods=['POST'])
def check_team_creator():
    data = request.get_json()
    team_id = data.get('team_id')
    user_id = data.get('user_id')
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        result = c.fetchone()
        if result:
            return jsonify({"is_creator": result[0] == user_id})
        return jsonify({"is_creator": False}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Error in check_team_creator: {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Ensure database is initialized at startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)