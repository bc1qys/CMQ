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
        # Table Documentation
        c.execute('''CREATE TABLE IF NOT EXISTS documentation_articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT,
                    tags TEXT,
                    difficulty_level TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
        app.logger.debug("Table documentation_articles vérifiée/créée.")
        # Table challenge résolu
        c.execute('''CREATE TABLE IF NOT EXISTS solved_challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    challenge_id INTEGER NOT NULL,
                    user_id INTEGER, -- Qui a soumis le flag dans l'équipe (optionnel mais utile)
                    solved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                    FOREIGN KEY (challenge_id) REFERENCES challenges(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                    UNIQUE (team_id, challenge_id)
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
    session.pop('user_id', None) # Effacer aussi user_id au cas où un admin était aussi loggé en user
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
    # preferred_role n'est plus envoyé par le client pour l'inscription standard
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        # preferred_role est inséré comme NULL pour les nouveaux utilisateurs
        c.execute("INSERT INTO users (username, password, preferred_role) VALUES (?, ?, NULL)",
                  (username, hashed_password))
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
            if result[2] == 'admin': # preferred_role est utilisé ici pour identifier l'admin
                session['admin_id'] = result[0]
                app.logger.debug(f"Connexion admin réussie : username={username}, admin_id={result[0]}")
                return jsonify({
                    "message": "Connexion admin réussie",
                    "redirect": "/admin"
                })
            else:
                session['user_id'] = result[0]
                session['username'] = username
                session['preferred_role'] = result[2] # Sera NULL pour les joueurs
                app.logger.debug(f"Connexion joueur réussie : username={username}, user_id={result[0]}, session['user_id']={result[0]}")
                return jsonify({
                    "message": "Connexion réussie",
                    "user_id": result[0],
                    "preferred_role": result[2], # Sera null pour les joueurs
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
        # La requête corrigée pour inclure les preferred_role NULL
        c.execute("SELECT id, username, preferred_role, score FROM users WHERE preferred_role IS NULL OR preferred_role != 'admin'")
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
@app.route('/register', methods=['POST']) # Note: cette route est généralement nommée /register_team
def register_team():
    if 'user_id' not in session:
        app.logger.debug("Inscription équipe échouée : pas de user_id dans la session")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    role = data.get('role')
    user_id = session['user_id']
    
    app.logger.debug(f"register_team: user_id={user_id}")
    
    if not name or not password or role not in ['attaque', 'defense']:
        app.logger.debug("Inscription équipe échouée : données invalides")
        return jsonify({"message": "Données invalides"}), 400
    
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
        app.logger.error(f"Erreur dans register : {e}") # Doit être register_team
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Connexion équipe
@app.route('/login_team', methods=['POST']) # Note: cette route est /login dans index.html, devrait être cohérent
def login_team():
    if 'user_id' not in session: # L'utilisateur doit être connecté pour se connecter à une équipe? Ou est-ce une connexion d'équipe distincte?
        app.logger.debug("Connexion équipe échouée : pas de user_id") # Peut-être pas nécessaire si c'est une action d'équipe
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
            team_id = result[0]
            team_role = result[2]
            # Vérifier si l'utilisateur actuel est membre de cette équipe avant de mettre à jour la session?
            # Ou est-ce que "login_team" ajoute l'utilisateur à l'équipe s'il n'y est pas?
            # Actuellement, il met juste l'équipe dans la session de l'utilisateur.
            # Si l'utilisateur n'est pas dans l'équipe mais se connecte "en tant qu'équipe", il faut clarifier.
            # Pour l'instant, on assume que l'utilisateur qui fait "login_team" veut s'associer à cette équipe dans sa session.
            
            # Ajoutons une vérification pour voir si l'utilisateur est déjà dans une équipe différente ou
            # s'il peut rejoindre celle-ci.
            # Pour l'instant, on suit la logique originale, qui est de mettre l'équipe dans la session.
            # Il est possible que login_team soit utilisé pour "rejoindre en entrant le mot de passe de l'équipe".

            session['team_id'] = team_id
            session['team_role'] = team_role
            session['team_name'] = name

            # S'assurer que l'utilisateur est bien lié à cette équipe dans user_teams
            # S'il n'y est pas, l'ajouter? Ou est-ce que c'est le rôle de /join_team ?
            # Pour l'instant, on n'ajoute pas automatiquement à user_teams ici.
            # /join_team est plus explicite pour cela.

            app.logger.debug(f"Connexion équipe réussie : name={name}, team_id={team_id}")
            return jsonify({
                "message": "Connexion réussie",
                "team_id": team_id,
                "team_role": team_role,
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
    user_id = session['user_id']
    team_id_to_join = data.get('team_id')
    password_attempt = data.get('password') # Récupérer le mot de passe fourni

    app.logger.debug(f"join_team: user_id={user_id}, team_id={team_id_to_join}")

    if not team_id_to_join or not password_attempt: # Vérifier si l'ID et le mot de passe sont fournis
        return jsonify({"message": "L'ID de l'équipe et le mot de passe sont requis."}), 400

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()

        # Récupérer aussi le mot de passe hashé de l'équipe
        c.execute("SELECT id, role, name, password FROM teams WHERE id = ?", (team_id_to_join,))
        team_data_tuple = c.fetchone() 

        if not team_data_tuple:
            app.logger.debug(f"Rejoindre équipe échoué : team_id={team_id_to_join} invalide")
            return jsonify({"message": "Équipe non trouvée."}), 404

        # team_data_tuple contient (id, role, name, hashed_password_db)
        team_id_db, team_role_db, team_name_db, hashed_password_db = team_data_tuple

        # Vérifier le mot de passe de l'équipe
        if not bcrypt.checkpw(password_attempt.encode('utf-8'), hashed_password_db):
            app.logger.debug(f"Tentative de rejoindre l'équipe {team_id_to_join} échouée : mot de passe incorrect.")
            return jsonify({"message": "Mot de passe de l'équipe incorrect."}), 403 # 403 Forbidden

        # Vérifier si l'utilisateur est déjà dans une équipe
        c.execute("SELECT team_id FROM user_teams WHERE user_id = ?", (user_id,))
        current_team_membership = c.fetchone()
        if current_team_membership:
            app.logger.debug(f"Rejoindre équipe échoué : user_id={user_id} déjà dans l'équipe {current_team_membership[0]}")
            return jsonify({"message": "Vous êtes déjà dans une équipe."}), 400

        # Si tout est OK, ajouter l'utilisateur à l'équipe
        c.execute("INSERT INTO user_teams (user_id, team_id) VALUES (?, ?)", (user_id, team_id_db))
        conn.commit()
        session['team_id'] = team_id_db
        session['team_role'] = team_role_db 
        session['team_name'] = team_name_db 
        app.logger.debug(f"Utilisateur {user_id} a rejoint l'équipe {team_id_db} ('{team_name_db}')")
        return jsonify({"message": "Équipe rejointe avec succès !", "team_id": team_id_db, "team_role": team_role_db, "team_name": team_name_db})

    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite dans join_team : {e}")
        return jsonify({"message": "Erreur serveur lors de la tentative de rejoindre l'équipe."}), 500
    except Exception as e:
        app.logger.error(f"Erreur générale dans join_team : {e}")
        return jsonify({"message": "Erreur serveur inattendue."}), 500
    finally:
        if conn:
            conn.close()

# Quitter une équipe
@app.route('/leave_team', methods=['POST'])
def leave_team():
    if 'user_id' not in session:
        app.logger.debug("Quitter équipe échoué : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    user_id = session['user_id']
    
    app.logger.debug(f"leave_team: user_id={user_id}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        # Vérifier si l'utilisateur est dans une équipe
        c.execute("SELECT team_id FROM user_teams WHERE user_id = ?", (user_id,))
        user_team_membership = c.fetchone()
        
        if user_team_membership:
            team_id_to_leave = user_team_membership[0]
            c.execute("DELETE FROM user_teams WHERE user_id = ? AND team_id = ?", (user_id, team_id_to_leave))
            conn.commit()
            
            # Effacer les informations de l'équipe de la session
            session.pop('team_id', None)
            session.pop('team_role', None)
            session.pop('team_name', None)
            app.logger.debug(f"Utilisateur a quitté l'équipe : user_id={user_id}, team_id={team_id_to_leave}")
            return jsonify({"message": "Équipe quittée avec succès"})
        else:
            app.logger.debug(f"Quitter équipe échoué : user_id={user_id} pas dans une équipe")
            # Peut-être nettoyer la session au cas où elle serait incohérente
            session.pop('team_id', None)
            session.pop('team_role', None)
            session.pop('team_name', None)
            return jsonify({"message": "Vous n'êtes pas dans une équipe"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans leave_team : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Rejoindre un match
@app.route('/join_match', methods=['POST'])
def join_match():
    if 'user_id' not in session or 'team_id' not in session: # L'utilisateur doit être connecté et dans une équipe
        app.logger.debug("Rejoindre match échoué : pas de user_id ou team_id dans la session")
        return jsonify({"message": "Connexion et appartenance à une équipe requises"}), 401
    
    data = request.get_json()
    # team_id est pris de la session, pas de data.get('team_id')
    team_id = session['team_id']
    match_id = data.get('match_id')
    user_id = session['user_id']
    
    app.logger.debug(f"join_match: user_id={user_id}, team_id={team_id}, match_id={match_id}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        team_creator_info = c.fetchone() # Renommé pour clarté
        if not team_creator_info:
            app.logger.debug(f"Rejoindre match échoué : team_id={team_id} invalide")
            return jsonify({"message": "Équipe invalide"}), 400
        if team_creator_info[0] != user_id:
            app.logger.debug(f"Rejoindre match échoué : user_id={user_id} n'est pas créateur de team_id={team_id}")
            return jsonify({"message": "Seul le créateur de l'équipe peut engager l'équipe dans un match"}), 403
        
        c.execute("SELECT id, challenge_id, vm_id, ip_address FROM matches WHERE id = ? AND status = 'en cours'", (match_id,))
        match_info = c.fetchone() # Renommé
        
        if match_info:
            actual_match_id, challenge_id, vm_id, ip_address = match_info

            # Vérifier si l'équipe est déjà dans ce match pour ce challenge
            c.execute("""SELECT tm.id FROM team_matches tm
                         JOIN matches m ON tm.match_id = m.id
                         WHERE tm.team_id = ? AND m.challenge_id = ?""", (team_id, challenge_id))
            existing_team_match_for_challenge = c.fetchone()
            if existing_team_match_for_challenge:
                 app.logger.debug(f"L'équipe {team_id} est déjà dans un match pour le challenge {challenge_id}")
                 # Optionnel: retourner les infos existantes ou un message spécifique
                 # Pour l'instant, on interdit de rejoindre un "nouveau" match pour le même challenge si déjà engagé
                 # Ou alors, on permet de rejoindre le *même* match_id si la session a été perdue.
                 # Le code actuel insère une nouvelle ligne dans team_matches, ce qui peut être problématique.
                 # Vérifions si l'équipe est DÉJÀ dans CE match_id précis:
                 c.execute("SELECT access_token FROM team_matches WHERE team_id = ? AND match_id = ?", (team_id, actual_match_id))
                 already_in_this_specific_match = c.fetchone()
                 if already_in_this_specific_match:
                    app.logger.debug(f"L'équipe {team_id} est déjà dans ce match spécifique {actual_match_id}.")
                    # On pourrait retourner les infos existantes
                    # Pour l'instant, on laisse la logique originale qui pourrait créer un doublon de token si pas géré
                    # La logique /submit_flag utilise "match_id IN (SELECT id FROM matches WHERE challenge_id = ?)"
                    # ce qui est bien, mais avoir plusieurs tokens pour le même (team,match) n'est pas idéal.
                    # Idéalement, on devrait avoir une contrainte UNIQUE(team_id, match_id) sur team_matches.
                    # Pour l'instant, nous allons suivre le code original qui permet de rejoindre (potentiellement à nouveau).

            access_token = secrets.token_hex(16)
            c.execute("INSERT INTO team_matches (team_id, match_id, access_token) VALUES (?, ?, ?)",
                      (team_id, actual_match_id, access_token))
            conn.commit()
            app.logger.debug(f"Équipe a rejoint le match : team_id={team_id}, match_id={actual_match_id}")
            return jsonify({
                "message": "Match rejoint !",
                "vm_ip": ip_address,
                "access_token": access_token,
                "guacamole_url": f"http://192.168.1.100/guacamole?token={access_token}" # L'IP Guacamole doit être configurable
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
    if 'user_id' not in session or 'team_id' not in session:
        app.logger.debug("Quitter match échoué : pas de user_id ou team_id")
        return jsonify({"message": "Connexion et appartenance à une équipe requises"}), 401
    
    data = request.get_json()
    team_id = session['team_id'] # Utiliser team_id de la session
    match_id_to_leave = data.get('match_id') # ID du match spécifique à quitter
    user_id = session['user_id'] # Pour vérifier si c'est le créateur qui quitte?

    app.logger.debug(f"leave_match: user_id={user_id}, team_id={team_id}, match_id={match_id_to_leave}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        # Vérifier si c'est le créateur de l'équipe qui demande de quitter?
        # La logique actuelle permet à tout membre (ayant le team_id dans sa session) de faire quitter l'équipe du match.
        # C'est peut-être ok, ou à restreindre au créateur.

        c.execute("SELECT id FROM team_matches WHERE team_id = ? AND match_id = ?", (team_id, match_id_to_leave))
        result = c.fetchone()
        
        if result:
            c.execute("DELETE FROM team_matches WHERE team_id = ? AND match_id = ?", (team_id, match_id_to_leave))
            conn.commit()
            app.logger.debug(f"Équipe a quitté le match : team_id={team_id}, match_id={match_id_to_leave}")
            return jsonify({"message": "Match quitté avec succès"})
        else:
            app.logger.debug(f"Quitter match échoué : team_id={team_id} pas dans match_id={match_id_to_leave}")
            return jsonify({"message": "Votre équipe n'est pas enregistrée dans ce match !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans leave_match : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Soumettre un flag
@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    if 'user_id' not in session or 'team_id' not in session:
        app.logger.debug("Soumission flag échouée : pas de user_id ou team_id")
        return jsonify({"message": "Connexion et appartenance à une équipe requises"}), 401
    
    data = request.get_json()
    team_id = session['team_id'] # Utiliser team_id de la session
    flag_submitted = data.get('flag') # Renommé pour clarté
    user_id = session['user_id']
    
    app.logger.debug(f"submit_flag: user_id={user_id}, team_id={team_id}, flag={flag_submitted}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT role FROM teams WHERE id = ?", (team_id,))
        team_info = c.fetchone() # Renommé
        if not team_info or team_info[0] != 'attaque':
            app.logger.debug(f"Soumission flag échouée : team_id={team_id} (rôle {team_info[0] if team_info else 'N/A'}) n'est pas attaque")
            return jsonify({"message": "Seules les équipes en rôle d'attaque peuvent soumettre des flags"}), 403
        
        c.execute("SELECT id, points FROM challenges WHERE flag = ?", (flag_submitted,))
        challenge_info = c.fetchone() # Renommé
        
        if challenge_info:
            challenge_id, points = challenge_info
            # Vérifier si l'équipe est dans un match actif pour ce challenge_id
            c.execute("""SELECT tm.id FROM team_matches tm
                         JOIN matches m ON tm.match_id = m.id
                         WHERE tm.team_id = ? AND m.challenge_id = ? AND m.status = 'en cours'""",
                      (team_id, challenge_id))
            active_match_for_challenge = c.fetchone()

            if active_match_for_challenge:
                # Vérifier si ce flag pour ce challenge n'a pas déjà été soumis par cette équipe
                # (Nécessiterait une table de flags soumis par équipe/challenge)
                # Pour l'instant, on permet de marquer des points à chaque soumission correcte.
                # Ce n'est généralement pas souhaité. Il faut une table `solved_challenges (team_id, challenge_id)`.

                c.execute("UPDATE teams SET score = score + ? WHERE id = ?", (points, team_id))
                c.execute("UPDATE users SET score = score + ? WHERE id = ?", (points, user_id)) # Le score va à l'utilisateur qui soumet
                conn.commit()
                app.logger.debug(f"Flag soumis avec succès: team_id={team_id}, user_id={user_id}, challenge_id={challenge_id}, points={points}")
                return jsonify({"message": "Flag correct !", "points": points})
            else:
                app.logger.debug(f"Soumission flag échouée : team_id={team_id} pas dans un match actif pour challenge_id={challenge_id}")
                return jsonify({"message": "Votre équipe n'est pas inscrite à un match actif pour ce défi."}), 403
        else:
            app.logger.debug(f"Soumission flag échouée : flag '{flag_submitted}' invalide")
            return jsonify({"message": "Flag incorrect !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans submit_flag : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Soumettre une défense
@app.route('/submit_defense', methods=['POST'])
def submit_defense():
    if 'user_id' not in session or 'team_id' not in session:
        app.logger.debug("Soumission défense échouée : pas de user_id ou team_id")
        return jsonify({"message": "Connexion et appartenance à une équipe requises"}), 401
    
    data = request.get_json()
    team_id = session['team_id'] # Utiliser team_id de la session
    challenge_id = data.get('challenge_id')
    proof = data.get('proof')
    user_id = session['user_id']
    
    app.logger.debug(f"submit_defense: user_id={user_id}, team_id={team_id}, challenge_id={challenge_id}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT role FROM teams WHERE id = ?", (team_id,))
        team_info = c.fetchone()
        if not team_info or team_info[0] != 'defense':
            app.logger.debug(f"Soumission défense échouée : team_id={team_id} (rôle {team_info[0] if team_info else 'N/A'}) n'est pas défense")
            return jsonify({"message": "Seules les équipes en rôle de défense peuvent soumettre des preuves"}), 403
        
        c.execute("SELECT points FROM challenges WHERE id = ?", (challenge_id,))
        challenge_info = c.fetchone()
        
        if challenge_info:
            points = challenge_info[0]
            # Vérifier si l'équipe est dans un match actif pour ce challenge_id où elle doit défendre?
            # La logique actuelle ne lie pas directement la soumission de défense à un match spécifique,
            # seulement au challenge_id. C'est peut-être ok.

            # Vérifier si une défense pour ce challenge n'a pas déjà été soumise/validée par cette équipe
            # (Nécessiterait une colonne de statut dans `defenses` ou une table séparée)
            # Actuellement, on peut soumettre plusieurs fois.

            c.execute("INSERT INTO defenses (team_id, challenge_id, proof) VALUES (?, ?, ?)",
                      (team_id, challenge_id, proof))
            # L'attribution de points ici est automatique. Devrait-elle être validée par un admin?
            c.execute("UPDATE teams SET score = score + ? WHERE id = ?", (points, team_id))
            c.execute("UPDATE users SET score = score + ? WHERE id = ?", (points, user_id))
            conn.commit()
            app.logger.debug(f"Défense soumise : team_id={team_id}, user_id={user_id}, challenge_id={challenge_id}, points={points}")
            return jsonify({"message": "Preuve acceptée !", "points": points}) # "Acceptée" est peut-être fort si pas de validation
        else:
            app.logger.debug(f"Soumission défense échouée : challenge_id={challenge_id} invalide")
            return jsonify({"message": "Défi invalide !"}), 400
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans submit_defense : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Vérifier le créateur d'équipe
@app.route('/teams', methods=['POST']) # Cette route est appelée pour vérifier si on peut rejoindre un match
def check_team_creator():
    if 'user_id' not in session:
        app.logger.debug("Vérification créateur échouée : pas de user_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    data = request.get_json()
    team_id = data.get('team_id') # Ceci devrait être le team_id de la session de l'utilisateur
    user_id = session['user_id']

    # Il est plus sûr de prendre le team_id de la session si disponible
    if 'team_id' in session:
        team_id_from_session = session['team_id']
        if team_id is not None and int(team_id) != team_id_from_session : # team_id peut venir en string du JSON
             app.logger.warning(f"check_team_creator: team_id from request ({team_id}) differs from session ({team_id_from_session}) for user {user_id}")
             # Décider quelle source prioriser ou retourner une erreur
             # Pour l'instant, on utilise celui de la requête s'il est fourni, sinon celui de la session.
             # Mais home.html envoie le team_id de son sessionStorage, qui devrait correspondre à session['team_id']
        if team_id is None:
             team_id = team_id_from_session

    if team_id is None: # Si toujours None après vérification session
        app.logger.debug(f"check_team_creator: team_id non fourni et non trouvé en session pour user_id={user_id}")
        return jsonify({"message": "Information d'équipe manquante"}), 400
        
    app.logger.debug(f"check_team_creator: user_id={user_id}, team_id={team_id}")
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        result = c.fetchone()
        if result:
            is_creator = (result[0] == user_id)
            app.logger.debug(f"Vérification créateur : team_id={team_id}, creator_id_db={result[0]}, user_id_session={user_id}, is_creator={is_creator}")
            return jsonify({"is_creator": is_creator})
        else:
            app.logger.debug(f"Vérification créateur échouée : team_id={team_id} invalide")
            return jsonify({"message": "Équipe non trouvée", "is_creator": False}), 404 # 404 Not Found
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans check_team_creator : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Classement
@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    # Pas besoin de user_id en session pour voir le leaderboard public?
    # Si c'est une section protégée, alors la vérification est ok.
    if 'user_id' not in session and 'admin_id' not in session : # Ou admin
        app.logger.debug("Accès classement refusé : pas de user_id ou admin_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        # Exclure l'admin du classement des joueurs.
        # La condition preferred_role != 'admin' OU preferred_role IS NULL est déjà utilisée pour admin_players.
        c.execute("SELECT username, score, preferred_role FROM users WHERE preferred_role IS NULL OR preferred_role != 'admin' ORDER BY score DESC")
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
    if 'user_id' not in session and 'admin_id' not in session:
        app.logger.debug("Accès challenges refusé : pas de user_id ou admin_id")
        return jsonify({"message": "Connexion requise"}), 401
    
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        c.execute("SELECT id, name, description, points, level FROM challenges") # Ajout ID et description
        challenges_data = []
        for row in c.fetchall():
            challenge_id, name, description, points, level = row
            # Potentiellement, ajouter si le challenge est résolu par l'équipe de l'utilisateur
            challenges_data.append({
                "id": challenge_id, # Renvoyer l'ID peut être utile
                "name": name,
                "description": description, # Renvoyer la description
                "points": points,
                "level": level
            })
        return jsonify({"challenges": challenges_data})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur dans challenges : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        conn.close()

# Supprimer un joueur (admin)
@app.route('/admin/delete_player/<int:player_id>', methods=['DELETE'])
def admin_delete_player(player_id):
    if 'admin_id' not in session:
        app.logger.debug(f"Tentative de suppression du joueur {player_id} refusée : pas de admin_id")
        return jsonify({"message": "Connexion admin requise"}), 401

    app.logger.info(f"Tentative de suppression du joueur ID: {player_id} par l'admin ID: {session['admin_id']}")
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        # Vérifier si le joueur à supprimer n'est pas l'admin lui-même (sécurité)
        c.execute("SELECT username, preferred_role FROM users WHERE id = ?", (player_id,))
        player_to_delete = c.fetchone()
        if player_to_delete and player_to_delete[1] == 'admin': #  player_to_delete[1] est preferred_role
            app.logger.warning(f"Tentative de suppression du compte admin (ID: {player_id}) refusée.")
            return jsonify({"message": "Vous не pouvez pas supprimer le compte administrateur principal."}), 403

        # 1. Mettre à NULL creator_id dans la table 'teams' pour les équipes créées par ce joueur
        c.execute("UPDATE teams SET creator_id = NULL WHERE creator_id = ?", (player_id,))
        app.logger.debug(f"creator_id mis à NULL pour les équipes créées par le joueur ID: {player_id}")

        # 2. Supprimer les appartenances de ce joueur aux équipes dans 'user_teams'
        c.execute("DELETE FROM user_teams WHERE user_id = ?", (player_id,))
        app.logger.debug(f"Appartenances aux équipes supprimées pour le joueur ID: {player_id}")

        # 3. Supprimer le joueur de la table 'users'
        delete_result = c.execute("DELETE FROM users WHERE id = ?", (player_id,))
        conn.commit()

        if delete_result.rowcount > 0:
            app.logger.info(f"Joueur ID: {player_id} supprimé avec succès.")
            return jsonify({"message": "Joueur supprimé avec succès"})
        else:
            app.logger.warning(f"Aucun joueur trouvé avec l'ID: {player_id} pour suppression.")
            return jsonify({"message": "Joueur non trouvé"}), 404

    except sqlite3.Error as e:
        conn.rollback()
        app.logger.error(f"Erreur lors de la suppression du joueur ID: {player_id} : {e}")
        return jsonify({"message": "Erreur serveur lors de la suppression du joueur"}), 500
    finally:
        conn.close()

# Supprimer une équipe (admin)
@app.route('/admin/delete_team/<int:team_id>', methods=['DELETE'])
def admin_delete_team(team_id):
    if 'admin_id' not in session:
        app.logger.debug(f"Tentative de suppression de l'équipe {team_id} refusée : pas de admin_id")
        return jsonify({"message": "Connexion admin requise"}), 401

    app.logger.info(f"Tentative de suppression de l'équipe ID: {team_id} par l'admin ID: {session['admin_id']}")
    conn = sqlite3.connect('ctf.db')
    c = conn.cursor()
    try:
        # 1. Supprimer les appartenances des utilisateurs à cette équipe dans 'user_teams'
        c.execute("DELETE FROM user_teams WHERE team_id = ?", (team_id,))
        app.logger.debug(f"Membres de l'équipe ID: {team_id} supprimés de user_teams.")

        # 2. Supprimer les participations de cette équipe aux matchs dans 'team_matches'
        c.execute("DELETE FROM team_matches WHERE team_id = ?", (team_id,))
        app.logger.debug(f"Participations aux matchs de l'équipe ID: {team_id} supprimées de team_matches.")

        # 3. Supprimer les soumissions de défense de cette équipe dans 'defenses'
        c.execute("DELETE FROM defenses WHERE team_id = ?", (team_id,))
        app.logger.debug(f"Soumissions de défense de l'équipe ID: {team_id} supprimées de defenses.")
        
        # 4. Supprimer l'équipe de la table 'teams'
        delete_result = c.execute("DELETE FROM teams WHERE id = ?", (team_id,))
        conn.commit()

        if delete_result.rowcount > 0:
            app.logger.info(f"Équipe ID: {team_id} supprimée avec succès.")
            return jsonify({"message": "Équipe supprimée avec succès"})
        else:
            app.logger.warning(f"Aucune équipe trouvée avec l'ID: {team_id} pour suppression.")
            return jsonify({"message": "Équipe non trouvée"}), 404

    except sqlite3.Error as e:
        conn.rollback()
        app.logger.error(f"Erreur lors de la suppression de l'équipe ID: {team_id} : {e}")
        return jsonify({"message": "Erreur serveur lors de la suppression de l'équipe"}), 500
    finally:
        conn.close()
#Doc
@app.route('/api/documentation/articles', methods=['GET'])
def get_documentation_articles():
    # Assurez-vous que l'utilisateur est connecté pour accéder à la documentation
    if 'user_id' not in session and 'admin_id' not in session:
        # Renvoyer une erreur JSON, pas une redirection HTML
        return jsonify({"message": "Authentification requise pour accéder à la documentation."}), 401

    conn = None  # Initialiser conn à None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row # Pour accéder aux colonnes par leur nom
        c = conn.cursor()
        
        # Récupérer les champs utiles pour la liste
        c.execute("SELECT id, title, category, difficulty_level, tags FROM documentation_articles ORDER BY category, title")
        articles_raw = c.fetchall()
        
        articles_list = []
        if articles_raw:
            articles_list = [dict(row) for row in articles_raw]
            
        app.logger.debug(f"Articles de documentation récupérés : {len(articles_list)} articles.")
        return jsonify({"articles": articles_list})

    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite lors de la récupération des articles de documentation : {e}")
        return jsonify({"message": "Erreur serveur lors de la récupération de la documentation."}), 500
    except Exception as e:
        app.logger.error(f"Erreur générale lors de la récupération des articles de documentation : {e}")
        return jsonify({"message": "Erreur serveur inattendue."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/documentation/article/<int:article_id>', methods=['GET'])
def get_documentation_article(article_id):
    if 'user_id' not in session and 'admin_id' not in session:
        return jsonify({"message": "Authentification requise."}), 401

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute("SELECT id, title, content, category, difficulty_level, tags, created_at, updated_at FROM documentation_articles WHERE id = ?", (article_id,))
        article_raw = c.fetchone()
        
        if article_raw:
            article_dict = dict(article_raw)
            app.logger.debug(f"Article ID {article_id} trouvé : {article_dict['title']}")
            # Si vous stockez en Markdown et voulez le convertir en HTML ici :
            # import markdown
            # article_dict['content_html'] = markdown.markdown(article_dict['content'])
            # Puis envoyez 'content_html' au lieu de 'content' brut, ou en plus.
            return jsonify(article_dict)
        else:
            app.logger.warning(f"Aucun article de documentation trouvé avec l'ID: {article_id}")
            return jsonify({"message": "Article non trouvé."}), 404

    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite lors de la récupération de l'article ID {article_id} : {e}")
        return jsonify({"message": "Erreur serveur lors de la récupération de l'article."}), 500
    except Exception as e:
        app.logger.error(f"Erreur générale lors de la récupération de l'article ID {article_id} : {e}")
        return jsonify({"message": "Erreur serveur inattendue."}), 500
    finally:
        if conn:
            conn.close()
@app.route('/admin/documentation/create', methods=['POST'])
def admin_create_documentation():
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401

    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    category = data.get('category')
    tags = data.get('tags')
    difficulty_level = data.get('difficulty_level')

    if not title or not content:
        return jsonify({"message": "Le titre et le contenu sont obligatoires."}), 400

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        c.execute("""
            INSERT INTO documentation_articles (title, content, category, tags, difficulty_level, updated_at) 
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (title, content, category, tags, difficulty_level)) # created_at a déjà CURRENT_TIMESTAMP par défaut
        conn.commit()
        app.logger.info(f"Article de documentation créé : '{title}'")
        return jsonify({"message": "Article de documentation créé avec succès !"}), 201
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        app.logger.error(f"Erreur SQLite lors de la création de l'article de doc : {e}")
        return jsonify({"message": "Erreur serveur lors de la création de l'article."}), 500
    except Exception as e:
        if conn:
            conn.rollback() # Au cas où l'erreur se produit après la connexion mais avant le commit et n'est pas sqlite.Error
        app.logger.error(f"Erreur générale lors de la création de l'article de doc : {e}")
        return jsonify({"message": "Erreur serveur inattendue."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/dissolve_team', methods=['POST'])
def dissolve_team():
    if 'user_id' not in session:
        app.logger.warning("Tentative de dissolution d'équipe : utilisateur non connecté.")
        return jsonify({"message": "Connexion requise."}), 401
    if 'team_id' not in session:
        app.logger.warning(f"Tentative de dissolution d'équipe par user_id {session['user_id']} : pas de team_id en session.")
        return jsonify({"message": "Vous n'êtes pas dans une équipe ou votre session d'équipe a expiré."}), 400

    user_id = session['user_id']
    team_id_to_dissolve = session['team_id']
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()

        # Vérifier si l'utilisateur est bien le créateur de l'équipe
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id_to_dissolve,))
        team_data = c.fetchone()

        if not team_data:
            app.logger.warning(f"Tentative de dissolution de l'équipe {team_id_to_dissolve} par user_id {user_id} : équipe non trouvée.")
            # Nettoyer la session au cas où
            session.pop('team_id', None)
            session.pop('team_name', None)
            session.pop('team_role', None)
            session.pop('isTeamCreator', None)
            return jsonify({"message": "Équipe non trouvée."}), 404

        if team_data[0] != user_id:
            app.logger.warning(f"Tentative de dissolution de l'équipe {team_id_to_dissolve} par user_id {user_id} : non autorisé (pas le créateur).")
            return jsonify({"message": "Seul le créateur de l'équipe peut la dissoudre."}), 403

        # Si l'utilisateur est le créateur, procéder à la dissolution
        app.logger.info(f"Dissolution de l'équipe ID: {team_id_to_dissolve} par le créateur ID: {user_id}")

        # 1. Supprimer les appartenances des utilisateurs à cette équipe dans 'user_teams'
        c.execute("DELETE FROM user_teams WHERE team_id = ?", (team_id_to_dissolve,))
        app.logger.debug(f"Membres de l'équipe ID: {team_id_to_dissolve} supprimés de user_teams.")

        # 2. Supprimer les participations de cette équipe aux matchs dans 'team_matches'
        c.execute("DELETE FROM team_matches WHERE team_id = ?", (team_id_to_dissolve,))
        app.logger.debug(f"Participations aux matchs de l'équipe ID: {team_id_to_dissolve} supprimées de team_matches.")

        # 3. Supprimer les soumissions de défense de cette équipe dans 'defenses'
        c.execute("DELETE FROM defenses WHERE team_id = ?", (team_id_to_dissolve,))
        app.logger.debug(f"Soumissions de défense de l'équipe ID: {team_id_to_dissolve} supprimées de defenses.")

        # 4. Supprimer les challenges résolus par cette équipe dans 'solved_challenges'
        c.execute("DELETE FROM solved_challenges WHERE team_id = ?", (team_id_to_dissolve,))
        app.logger.debug(f"Challenges résolus par l'équipe ID: {team_id_to_dissolve} supprimés de solved_challenges.")

        # 5. Supprimer l'équipe de la table 'teams'
        delete_result = c.execute("DELETE FROM teams WHERE id = ?", (team_id_to_dissolve,))
        conn.commit()

        if delete_result.rowcount > 0:
            # Nettoyer la session de l'utilisateur créateur
            session.pop('team_id', None)
            session.pop('team_name', None)
            session.pop('team_role', None)
            session.pop('isTeamCreator', None)
            app.logger.info(f"Équipe ID: {team_id_to_dissolve} dissoute avec succès.")
            return jsonify({"message": "Équipe dissoute avec succès."})
        else:
            # Ne devrait pas arriver si la vérification team_data a fonctionné
            app.logger.error(f"Échec de la suppression de l'équipe {team_id_to_dissolve} de la table 'teams' alors qu'elle existait.")
            return jsonify({"message": "Erreur lors de la suppression de l'équipe."}), 500

    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        app.logger.error(f"Erreur SQLite lors de la dissolution de l'équipe ID {team_id_to_dissolve} : {e}")
        return jsonify({"message": "Erreur serveur lors de la dissolution de l'équipe."}), 500
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.error(f"Erreur générale lors de la dissolution de l'équipe ID {team_id_to_dissolve} : {e}")
        return jsonify({"message": "Erreur serveur inattendue."}), 500
    finally:
        if conn:
            conn.close()

# Initialiser la base de données au démarrage
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)