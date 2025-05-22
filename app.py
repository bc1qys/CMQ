from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import bcrypt
import secrets
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Clé secrète pour les sessions

# Configurer les logs pour le débogage
logging.basicConfig(level=logging.DEBUG)

# Initialiser la base de données SQLite
def init_db():
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        app.logger.debug("Création des tables de la base de données...")
        
        # Table utilisateurs
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT,
                     preferred_role TEXT,
                     score INTEGER DEFAULT 0
                     )''')
        
        # Table équipes
        c.execute('''CREATE TABLE IF NOT EXISTS teams (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT UNIQUE,
                     password TEXT,
                     role TEXT,
                     score INTEGER DEFAULT 0,
                     creator_id INTEGER
                     )''')
        
        # Table relation utilisateurs-équipes
        c.execute('''CREATE TABLE IF NOT EXISTS user_teams (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     team_id INTEGER,
                     UNIQUE(user_id, team_id)
                     )''')
        
        # Table challenges
        c.execute('''CREATE TABLE IF NOT EXISTS challenges (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT,
                     description TEXT,
                     flag TEXT,
                     points INTEGER,
                     level TEXT
                     )''')
        
        # Table matchs
        c.execute('''CREATE TABLE IF NOT EXISTS matches (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     challenge_id INTEGER,
                     vm_id TEXT,
                     ip_address TEXT,
                     status TEXT
                     )''')
        
        # Table relation équipes-matchs
        c.execute('''CREATE TABLE IF NOT EXISTS team_matches (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     team_id INTEGER,
                     match_id INTEGER,
                     access_token TEXT
                     )''')
        
        # Table défenses
        c.execute('''CREATE TABLE IF NOT EXISTS defenses (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     team_id INTEGER,
                     challenge_id INTEGER,
                     proof TEXT
                     )''')
        
        # Créer le compte admin par défaut
        hashed_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT OR IGNORE INTO users (username, password, preferred_role, score) VALUES (?, ?, ?, ?)",
                  ('admin', hashed_password, 'admin', 0))
        
        conn.commit()
        app.logger.debug("Tables créées avec succès")
    except sqlite3.Error as e:
        app.logger.error(f"Échec de l'initialisation de la base de données : {e}")
    finally:
        conn.close()

# Page d'accueil
@app.route('/')
def index():
    if 'user_id' not in session and 'admin_id' not in session:
        app.logger.debug("Accès à / sans session, redirection vers /login")
        return redirect(url_for('login'))
    return render_template('home.html')

# Page de connexion
@app.route('/login')
def login():
    return render_template('login.html')

# Page admin (protégée)
@app.route('/admin')
def admin():
    if 'admin_id' not in session:
        app.logger.debug("Accès à /admin refusé : pas de admin_id dans la session")
        return redirect(url_for('login'))
    return render_template('admin.html')

# Déconnexion générale
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    app.logger.debug("Déconnexion utilisateur")
    return jsonify({"message": "Déconnexion réussie", "redirect": "/login"}), 200

# Déconnexion admin
@app.route('/admin_logout', methods=['POST'])
def admin_logout():
    session.pop('admin_id', None)
    session.pop('user_id', None)
    app.logger.debug("Déconnexion admin")
    return jsonify({"message": "Déconnexion admin réussie", "redirect": "/login"}), 200

# Inscription utilisateur
@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        app.logger.debug("Inscription échouée : username ou password manquant")
        return jsonify({"message": "Données invalides"}), 400
    
    username = data['username']
    password = data['password']
    preferred_role = data.get('preferred_role', '')
    
    # Restreindre preferred_role pour éviter admin
    if preferred_role not in ['attaque', 'defense', '']:
        app.logger.debug(f"Inscription échouée : preferred_role={preferred_role} invalide")
        return jsonify({"message": "Rôle préféré invalide"}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, preferred_role) VALUES (?, ?, ?)",
                  (username, hashed_password, preferred_role or None))
        conn.commit()
        app.logger.debug(f"Utilisateur inscrit : username={username}")
        return jsonify({"message": "Compte utilisateur créé"}), 201
    except sqlite3.IntegrityError:
        app.logger.debug(f"Inscription échouée : username={username} déjà pris")
        return jsonify({"message": "Nom d'utilisateur déjà pris"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans register_user : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Connexion utilisateur (admin ou joueur)
@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        app.logger.debug("Connexion échouée : username ou password manquant")
        return jsonify({"message": "Données invalides"}), 400
    
    username = data['username']
    password = data['password']
    app.logger.debug(f"Tentative de connexion : username={username}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, password, preferred_role FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        
        if result and bcrypt.checkpw(password.encode('utf-8'), result[1]):
            if result[2] == 'admin':
                # Connexion admin
                session['admin_id'] = result[0]
                app.logger.debug(f"Connexion admin réussie : username={username}, admin_id={result[0]}")
                return jsonify({
                    "message": "Connexion admin réussie",
                    "redirect": "/admin"
                })
            else:
                # Connexion joueur
                session['user_id'] = result[0]
                session['username'] = username
                session['preferred_role'] = result[2]
                app.logger.debug(f"Connexion joueur réussie : username={username}, user_id={result[0]}")
                return jsonify({
                    "message": "Connexion réussie",
                    "user_id": result[0],
                    "preferred_role": result[2],
                    "redirect": "/"
                })
        else:
            app.logger.debug("Connexion échouée : identifiants invalides")
            return jsonify({"message": "Nom ou mot de passe incorrect"}), 401
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans login_user : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Liste des joueurs (admin)
@app.route('/admin_players', methods=['GET'])
def admin_players():
    if 'admin_id' not in session:
        app.logger.debug("Accès à /admin_players refusé : pas de admin_id")
        return jsonify({"message": "Connexion admin requise"}), 401
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, username, preferred_role, score FROM users WHERE preferred_role != 'admin'")
        players = [{"id": row[0], "username": row[1], "preferred_role": row[2], "score": row[3]} for row in c.fetchall()]
        return jsonify({"players": players})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans admin_players : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Liste des équipes (admin)
@app.route('/admin_teams', methods=['GET'])
def admin_teams():
    if 'admin_id' not in session:
        app.logger.debug("Accès à /admin_teams refusé : pas de admin_id")
        return jsonify({"message": "Connexion admin requise"}), 401
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, name, role, creator_id FROM teams")
        teams = []
        for row in c.fetchall():
            team_id, name, role, creator_id = row
            c.execute("SELECT username FROM users WHERE id = ?", (creator_id,))
            result = c.fetchone()
            creator_username = result[0] if result else "Inconnu"
            c.execute("SELECT u.username FROM users u JOIN user_teams ut ON u.id = ut.user_id WHERE ut.team_id = ?", (team_id,))
            members = [r[0] for r in c.fetchall()]
            teams.append({
                "id": team_id,
                "name": name,
                "role": role,
                "creator_username": creator_username,
                "members": members
            })
        return jsonify({"teams": teams})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans admin_teams : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Créer un challenge (admin)
@app.route('/admin_create_challenge', methods=['POST'])
def admin_create_challenge():
    if 'admin_id' not in session:
        app.logger.debug("Accès à /admin_create_challenge refusé : pas de admin_id")
        return jsonify({"message": "Connexion admin requise"}), 401
    
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    level = data.get('level')
    points = data.get('points')
    flag = data.get('flag')
    ip = data.get('ip')
    
    if not name or not level or not points or not flag or level not in ['debutant', 'intermediaire', 'avance']:
        app.logger.debug("Création de challenge échouée : données invalides")
        return jsonify({"message": "Données invalides"}), 400
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO challenges (name, description, flag, points, level) VALUES (?, ?, ?, ?, ?)",
                  (name, description, flag, points, level))
        challenge_id = c.lastrowid
        if ip:
            c.execute("INSERT INTO matches (challenge_id, vm_id, ip_address, status) VALUES (?, ?, ?, ?)",
                      (challenge_id, f"vm_{challenge_id}", ip, 'en cours'))
        conn.commit()
        app.logger.debug(f"Challenge créé : id={challenge_id}, name={name}")
        return jsonify({"message": "Challenge créé avec succès"})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans admin_create_challenge : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Inscription équipe
@app.route('/register', methods=['POST'])
def register_team():
    if 'user_id' not in session:
        app.logger.debug("Inscription équipe échouée : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    role = data.get('role')
    user_id = data.get('user_id')
    
    if not name or not password or role not in ['attaque', 'defense'] or not user_id:
        app.logger.debug("Inscription équipe échouée : données invalides")
        return jsonify({"message": "Données invalides"}), 400
    
    if user_id != session['user_id']:
        app.logger.debug(f"Inscription équipe échouée : user_id={user_id} non autorisé")
        return jsonify({"message": "Utilisateur non autorisé"}), 403
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not c.fetchone():
            app.logger.debug(f"Inscription équipe échouée : user_id={user_id} invalide")
            return jsonify({"message": "Utilisateur invalide"}), 400
        
        c.execute("SELECT id FROM user_teams WHERE user_id = ?", (user_id,))
        if c.fetchone():
            app.logger.debug(f"Inscription équipe échouée : user_id={user_id} déjà dans une équipe")
            return jsonify({"message": "Vous êtes déjà dans une équipe"}), 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        c.execute("INSERT INTO teams (name, password, role, creator_id) VALUES (?, ?, ?, ?)",
                  (name, hashed_password, role, user_id))
        team_id = c.lastrowid
        c.execute("INSERT INTO user_teams (user_id, team_id) VALUES (?, ?)",
                  (user_id, team_id))
        conn.commit()
        session['team_id'] = team_id
        session['team_role'] = role
        session['team_name'] = name
        app.logger.debug(f"Équipe inscrite : name={name}, team_id={team_id}, user_id={user_id}")
        return jsonify({"message": "Inscription réussie", "team_id": team_id, "team_role": role, "team_name": name}), 201
    except sqlite3.IntegrityError:
        app.logger.debug(f"Inscription équipe échouée : nom={name} déjà pris")
        return jsonify({"message": "Nom d'équipe déjà pris"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans register : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Connexion équipe
@app.route('/login', methods=['POST'])
def login_team():
    if 'user_id' not in session:
        app.logger.debug("Connexion équipe échouée : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    app.logger.debug(f"Tentative de connexion équipe : name={name}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, password, role FROM teams WHERE name = ?", (name,))
        result = c.fetchone()
        
        if result and bcrypt.checkpw(password.encode('utf-8'), result[1]):
            session['team_id'] = result[0]
            session['team_role'] = result[2]
            session['team_name'] = name
            app.logger.debug(f"Connexion équipe réussie : name={name}, team_id={result[0]}")
            return jsonify({
                "message": "Connexion réussie",
                "team_id": result[0],
                "team_role": result[2],
                "team_name": name
            })
        else:
            app.logger.debug("Connexion équipe échouée : identifiants invalides")
            return jsonify({"message": "Nom ou mot de passe incorrect"}), 401
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans login_team : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Rejoindre une équipe
@app.route('/join_team', methods=['POST'])
def join_team():
    if 'user_id' not in session:
        app.logger.debug("Rejoindre équipe échoué : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    user_id = data.get('user_id')
    team_id = data.get('team_id')
    
    if user_id != session['user_id']:
        app.logger.debug(f"Rejoindre équipe échoué : user_id={user_id} non autorisé")
        return jsonify({"message": "Utilisateur non autorisé"}), 403
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        c.execute("SELECT id, role, name FROM teams WHERE id = ?", (team_id,))
        team = c.fetchone()
        
        if not user or not team:
            app.logger.debug(f"Rejoindre équipe échoué : user_id={user_id} ou team_id={team_id} invalide")
            return jsonify({"message": "Utilisateur ou équipe invalide"}), 400
        
        c.execute("SELECT id FROM user_teams WHERE user_id = ?", (user_id,))
        if c.fetchone():
            app.logger.debug(f"Rejoindre équipe échoué : user_id={user_id} déjà dans une équipe")
            return jsonify({"message": "Vous êtes déjà dans une équipe"}), 400
        
        c.execute("INSERT INTO user_teams (user_id, team_id) VALUES (?, ?)", (user_id, team_id))
        conn.commit()
        session['team_id'] = team_id
        session['team_role'] = team[1]
        session['team_name'] = team[2]
        app.logger.debug(f"Utilisateur a rejoint l'équipe : user_id={user_id}, team_id={team_id}")
        return jsonify({"message": "Équipe rejointe avec succès", "team_id": team_id, "team_role": team[1], "team_name": team[2]})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans join_team : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Quitter une équipe
@app.route('/leave_team', methods=['POST'])
def leave_team():
    if 'user_id' not in session:
        app.logger.debug("Quitter équipe échoué : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    user_id = data.get('user_id')
    
    if user_id != session['user_id']:
        app.logger.debug(f"Quitter équipe échoué : user_id={user_id} non autorisé")
        return jsonify({"message": "Utilisateur non autorisé"}), 403
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT id FROM user_teams WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if result:
            c.execute("DELETE FROM user_teams WHERE user_id = ?", (user_id,))
            conn.commit()
            session.pop('team_id', None)
            session.pop('team_role', None)
            session.pop('team_name', None)
            app.logger.debug(f"Utilisateur a quitté l'équipe : user_id={user_id}")
            return jsonify({"message": "Équipe quittée avec succès"})
        else:
            app.logger.debug(f"Quitter équipe échoué : user_id={user_id} pas dans une équipe")
            return jsonify({"message": "Vous n'êtes pas dans une équipe"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans leave_team : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Rejoindre un match
@app.route('/join_match', methods=['POST'])
def join_match():
    if 'user_id' not in session:
        app.logger.debug("Rejoindre match échoué : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    team_id = data.get('team_id')
    match_id = data.get('match_id')
    user_id = data.get('user_id')
    
    if user_id != session['user_id']:
        app.logger.debug(f"Rejoindre match échoué : user_id={user_id} non autorisé")
        return jsonify({"message": "Utilisateur non autorisé"}), 403
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        team = c.fetchone()
        if not team:
            app.logger.debug(f"Rejoindre match échoué : team_id={team_id} invalide")
            return jsonify({"message": "Équipe invalide"}), 400
        if team[0] != user_id:
            app.logger.debug(f"Rejoindre match échoué : user_id={user_id} n'est pas créateur")
            return jsonify({"message": "Seul le créateur de l'équipe peut rejoindre un match"}), 403
        
        c.execute("SELECT vm_id, ip_address FROM matches WHERE id = ? AND status = 'en cours'", (match_id,))
        match = c.fetchone()
        
        if match:
            vm_id, ip_address = match
            access_token = secrets.token_hex(16)
            c.execute("INSERT INTO team_matches (team_id, match_id, access_token) VALUES (?, ?, ?)",
                      (team_id, match_id, access_token))
            conn.commit()
            app.logger.debug(f"Équipe a rejoint le match : team_id={team_id}, match_id={match_id}")
            return jsonify({
                "message": "Match rejoint !",
                "vm_ip": ip_address,
                "access_token": access_token,
                "guacamole_url": f"http://192.168.1.100/guacamole?token={access_token}"
            })
        else:
            app.logger.debug(f"Rejoindre match échoué : match_id={match_id} invalide ou terminé")
            return jsonify({"message": "Match invalide ou terminé !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans join_match : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Quitter un match
@app.route('/leave_match', methods=['POST'])
def leave_match():
    if 'user_id' not in session:
        app.logger.debug("Quitter match échoué : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
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
            app.logger.debug(f"Équipe a quitté le match : team_id={team_id}, match_id={match_id}")
            return jsonify({"message": "Match quitté avec succès"})
        else:
            app.logger.debug(f"Quitter match échoué : team_id={team_id} pas dans match_id={match_id}")
            return jsonify({"message": "Vous n'êtes pas dans ce match !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans leave_match : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Soumettre un flag
@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    if 'user_id' not in session:
        app.logger.debug("Soumission flag échouée : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    team_id = data.get('team_id')
    flag = data.get('flag')
    user_id = session['user_id']
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT role FROM teams WHERE id = ?", (team_id,))
        role = c.fetchone()
        if not role or role[0] != 'attaque':
            app.logger.debug(f"Soumission flag échouée : team_id={team_id} n'est pas attaque")
            return jsonify({"message": "Seules les équipes attaque peuvent soumettre des flags"}), 403
        
        c.execute("SELECT id, points FROM challenges WHERE flag = ?", (flag,))
        result = c.fetchone()
        
        if result:
            challenge_id, points = result
            c.execute("SELECT id FROM team_matches WHERE team_id = ? AND match_id IN (SELECT id FROM matches WHERE challenge_id = ?)",
                      (team_id, challenge_id))
            if c.fetchone():
                c.execute("UPDATE teams SET score = score + ? WHERE id = ?", (points, team_id))
                c.execute("UPDATE users SET score = score + ? WHERE id = ?", (points, user_id))
                conn.commit()
                app.logger.debug(f"Flag soumis : team_id={team_id}, challenge_id={challenge_id}, points={points}")
                return jsonify({"message": "Flag correct !", "points": points})
            else:
                app.logger.debug(f"Soumission flag échouée : team_id={team_id} pas dans le match pour challenge_id={challenge_id}")
                return jsonify({"message": "Vous n'êtes pas inscrit à un match pour ce défi"}), 403
        else:
            app.logger.debug("Soumission flag échouée : flag invalide")
            return jsonify({"message": "Flag incorrect !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans submit_flag : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Soumettre une défense
@app.route('/submit_defense', methods=['POST'])
def submit_defense():
    if 'user_id' not in session:
        app.logger.debug("Soumission défense échouée : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    team_id = data.get('team_id')
    challenge_id = data.get('challenge_id')
    proof = data.get('proof')
    user_id = session['user_id']
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT role FROM teams WHERE id = ?", (team_id,))
        role = c.fetchone()
        if not role or role[0] != 'defense':
            app.logger.debug(f"Soumission défense échouée : team_id={team_id} n'est pas défense")
            return jsonify({"message": "Seule l'équipe défense peut soumettre des preuves"}), 403
        
        c.execute("SELECT points FROM challenges WHERE id = ?", (challenge_id,))
        result = c.fetchone()
        
        if result:
            points = result[0]
            c.execute("INSERT INTO defenses (team_id, challenge_id, proof) VALUES (?, ?, ?)",
                      (team_id, challenge_id, proof))
            c.execute("UPDATE teams SET score = score + ? WHERE id = ?", (points, team_id))
            c.execute("UPDATE users SET score = score + ? WHERE id = ?", (points, user_id))
            conn.commit()
            app.logger.debug(f"Défense soumise : team_id={team_id}, challenge_id={challenge_id}, points={points}")
            return jsonify({"message": "Preuve acceptée !", "points": points})
        else:
            app.logger.debug(f"Soumission défense échouée : challenge_id={challenge_id} invalide")
            return jsonify({"message": "Défi invalide !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans submit_defense : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Vérifier le créateur d'équipe
@app.route('/teams', methods=['POST'])
def check_team_creator():
    if 'user_id' not in session:
        app.logger.debug("Vérification créateur échouée : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    team_id = data.get('team_id')
    user_id = data.get('user_id')
    
    if user_id != session['user_id']:
        app.logger.debug(f"Vérification créateur échouée : user_id={user_id} non autorisé")
        return jsonify({"message": "Utilisateur non autorisé"}), 403
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        result = c.fetchone()
        if result:
            app.logger.debug(f"Vérification créateur : team_id={team_id}, is_creator={result[0] == user_id}")
            return jsonify({"is_creator": result[0] == user_id})
        app.logger.debug(f"Vérification créateur échouée : team_id={team_id} invalide")
        return jsonify({"is_creator": False}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans check_team_creator : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Classement
@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    if 'user_id' not in session:
        app.logger.debug("Accès classement refusé : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT username, score, preferred_role FROM users WHERE preferred_role != 'admin' ORDER BY score DESC")
        players = [{"username": row[0], "score": row[1], "preferred_role": row[2]} for row in c.fetchall()]
        return jsonify({"players": players})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans leaderboard : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Liste des challenges
@app.route('/challenges', methods=['GET'])
def challenges():
    if 'user_id' not in session:
        app.logger.debug("Accès challenges refusé : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT name, points, level FROM challenges")
        challenges = [{"name": row[0], "points": row[1], "level": row[2]} for row in c.fetchall()]
        return jsonify({"challenges": challenges})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans challenges : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Initialiser la base de données au démarrage
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)