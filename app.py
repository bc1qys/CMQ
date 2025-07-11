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
        # Table feedback
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             user_id INTEGER,                       -- Qui a soumis le feedback (peut être NULL si anonyme ou non connecté)
             username TEXT,                         -- Nom de l'utilisateur qui soumet (pour affichage facile)
             timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
             type TEXT NOT NULL,                    -- Ex: 'Problème Challenge', 'Suggestion', 'Bug Interface', 'Autre'
             challenge_id_associated INTEGER,       -- Optionnel, si le feedback concerne un challenge spécifique
             subject TEXT,                          -- Un sujet court pour le feedback
             message TEXT NOT NULL,
             status TEXT DEFAULT 'Nouveau',         -- Ex: 'Nouveau', 'En cours', 'Résolu', 'Fermé'
             FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
             FOREIGN KEY (challenge_id_associated) REFERENCES challenges(id) ON DELETE SET NULL 
             )''')
        app.logger.debug("Table feedback vérifiée/créée.")
        
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
        return jsonify({"message": "Données invalides"}), 400
    
    username = data['username']
    password = data['password']
    app.logger.debug(f"Tentative de connexion : username={username}")
    
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row # Important pour accéder aux colonnes par nom
        c = conn.cursor()
        c.execute("SELECT id, password, preferred_role FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
            # Si le mot de passe est correct
            user_id = user_data['id']
            user_role = user_data['preferred_role']

            if user_role == 'admin':
                session['admin_id'] = user_id
                app.logger.debug(f"Connexion admin réussie : username={username}, admin_id={user_id}")
                return jsonify({"message": "Connexion admin réussie", "redirect": "/admin"})
            else:
                # C'est un joueur, on met ses infos de base en session
                session['user_id'] = user_id
                session['username'] = username
                session['preferred_role'] = user_role
                
                # --- NOUVELLE LOGIQUE : Chercher l'équipe de l'utilisateur ---
                c.execute("SELECT team_id FROM user_teams WHERE user_id = ?", (user_id,))
                team_membership = c.fetchone()
                
                response_data = {
                    "message": "Connexion réussie",
                    "user_id": user_id,
                    "preferred_role": user_role,
                    "redirect": "/"
                }

                if team_membership:
                    team_id = team_membership['team_id']
                    c.execute("SELECT id, name, role, creator_id FROM teams WHERE id = ?", (team_id,))
                    team_data = c.fetchone()
                    
                    if team_data:
                        # Ajouter les infos de l'équipe à la session serveur
                        session['team_id'] = team_data['id']
                        session['team_name'] = team_data['name']
                        session['team_role'] = team_data['role']
                        
                        # Ajouter les infos de l'équipe à la réponse JSON pour le client
                        response_data['team_id'] = team_data['id']
                        response_data['team_name'] = team_data['name']
                        response_data['team_role'] = team_data['role']
                        response_data['is_creator'] = (user_id == team_data['creator_id'])
                        app.logger.debug(f"Utilisateur {user_id} est dans l'équipe {team_id}. Infos ajoutées à la session.")
                
                app.logger.debug(f"Connexion joueur réussie : username={username}, user_id={user_id}")
                return jsonify(response_data)
        else:
            app.logger.debug(f"Connexion échouée pour {username} : identifiants invalides")
            return jsonify({"message": "Nom ou mot de passe incorrect"}), 401
    except Exception as e:
        app.logger.error(f"Erreur dans login_user : {e}")
        return jsonify({"message": "Erreur serveur"}), 500
    finally:
        if conn:
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
    if 'user_id' not in session or 'team_id' not in session:
        return jsonify({"message": "Connexion et appartenance à une équipe requises."}), 401
    
    user_id = session['user_id']
    team_id = session['team_id']
    data = request.get_json()
    match_id = data.get('match_id')

    if not match_id:
        return jsonify({"message": "ID de match manquant."}), 400
    
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # --- NOUVELLE VÉRIFICATION : L'équipe est-elle déjà dans un match actif ? ---
        c.execute("""
            SELECT tm.match_id FROM team_matches tm
            JOIN matches m ON tm.match_id = m.id
            WHERE tm.team_id = ? AND m.status = 'en cours'
        """, (team_id,))
        active_match = c.fetchone()
        if active_match:
            conn.close() # Important de fermer la connexion avant de retourner la réponse
            return jsonify({"message": f"Votre équipe est déjà engagée dans le match ID {active_match['match_id']}. Veuillez d'abord quitter ce match."}), 400
        # --- FIN DE LA VÉRIFICATION ---

        # Vérifier si l'utilisateur est le créateur (logique existante)
        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        team_info = c.fetchone()
        if not team_info or team_info['creator_id'] != user_id:
            return jsonify({"message": "Seul le créateur de l'équipe peut engager l'équipe dans un match."}), 403
        
        # Vérifier si le match à rejoindre existe et est disponible
        c.execute("SELECT id, challenge_id, ip_address FROM matches WHERE id = ? AND (status = 'disponible' OR status = 'en cours')", (match_id,))
        match_data = c.fetchone()
        if not match_data:
            return jsonify({"message": "Match non trouvé ou non disponible."}), 404
        
        # Le reste de la logique pour rejoindre le match
        access_token = secrets.token_hex(16)
        c.execute("INSERT INTO team_matches (team_id, match_id, access_token) VALUES (?, ?, ?)",
                  (match_data['id'], team_id, access_token)) # Ordre corrigé : team_id, match_id
        conn.commit()

        guacamole_ip = "192.168.1.100" # À rendre configurable
        return jsonify({
            "message": "Match rejoint !",
            "vm_ip": match_data['ip_address'],
            "access_token": access_token,
            "guacamole_url": f"http://{guacamole_ip}/guacamole?token={access_token}"
        })

    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite - join_match: {e}")
        return jsonify({"message": "Erreur serveur."}), 500
    finally:
        if conn:
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

@app.route('/api/documentation/articles', methods=['GET'])
def get_public_articles():
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, title, category, tags, difficulty_level FROM documentation_articles ORDER BY id DESC")
        articles = [dict(row) for row in c.fetchall()]
        return jsonify({"articles": articles})
    except Exception as e:
        app.logger.error(f"Erreur SQLite - get_public_articles: {e}")
        return jsonify({"message": "Erreur serveur."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/documentation/article/<int:article_id>', methods=['GET'])
def get_public_article(article_id):
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, title, content, category, tags, difficulty_level FROM documentation_articles WHERE id = ?", (article_id,))
        row = c.fetchone()
        if row:
            return jsonify(dict(row))
        else:
            return jsonify({"message": "Article non trouvé."}), 404
    except Exception as e:
        app.logger.error(f"Erreur SQLite - get_public_article: {e}")
        return jsonify({"message": "Erreur serveur."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/api/documentation', methods=['GET'])
def admin_get_documentation():
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401
    
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, title, category, difficulty_level FROM documentation_articles ORDER BY id DESC")
        articles = [dict(row) for row in c.fetchall()]
        return jsonify({"articles": articles})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite - admin_get_documentation: {e}")
        return jsonify({"message": "Erreur serveur."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/documentation/delete/<int:article_id>', methods=['DELETE'])
def admin_delete_documentation(article_id):
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401
    
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        delete_result = c.execute("DELETE FROM documentation_articles WHERE id = ?", (article_id,))
        conn.commit()

        if delete_result.rowcount > 0:
            app.logger.info(f"Article de documentation ID: {article_id} supprimé par admin ID {session['admin_id']}")
            return jsonify({"message": "Article supprimé avec succès."})
        else:
            return jsonify({"message": "Article non trouvé."}), 404
    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite - admin_delete_documentation: {e}")
        return jsonify({"message": "Erreur serveur lors de la suppression."}), 500
    finally:
        if conn:
            conn.close()

# Optionnel : Route pour récupérer un article (utile pour un futur formulaire de modification)
@app.route('/admin/api/documentation/<int:article_id>', methods=['GET'])
def admin_get_single_documentation(article_id):
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401
    
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM documentation_articles WHERE id = ?", (article_id,))
        article = c.fetchone()
        if article:
            return jsonify(dict(article))
        else:
            return jsonify({"message": "Article non trouvé."}), 404
    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite - admin_get_single_documentation: {e}")
        return jsonify({"message": "Erreur serveur."}), 500
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

@app.route('/api/feedback/submit', methods=['POST'])
def submit_feedback():
    if 'user_id' not in session:
        # Permettre un feedback anonyme ou refuser si l'utilisateur doit être connecté
        # Pour l'instant, on récupère user_id et username s'ils existent, sinon on met NULL/Anonyme
        user_id = None
        username = "Anonyme" 
        # Si la connexion est obligatoire pour le feedback :
        # return jsonify({"message": "Connexion requise pour soumettre un feedback."}), 401
    else:
        user_id = session['user_id']
        username = session.get('username', 'Utilisateur Inconnu') # Utiliser .get pour éviter KeyError

    data = request.get_json()
    feedback_type = data.get('type')
    challenge_id_associated = data.get('challenge_id_associated') # Peut être null
    subject = data.get('subject')
    message = data.get('message')

    if not feedback_type or not message or not subject:
        return jsonify({"message": "Le type, le sujet et le message du feedback sont obligatoires."}), 400

    # Conversion optionnelle de l'ID du challenge en entier si fourni
    if challenge_id_associated:
        try:
            challenge_id_associated = int(challenge_id_associated)
        except ValueError:
            return jsonify({"message": "L'ID du challenge associé doit être un nombre."}), 400
    else:
        challenge_id_associated = None # S'assurer qu'il est bien NULL si non fourni ou vide

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        c.execute("""
            INSERT INTO feedback (user_id, username, type, challenge_id_associated, subject, message) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, username, feedback_type, challenge_id_associated, subject, message))
        conn.commit()
        app.logger.info(f"Feedback soumis par {'user_id ' + str(user_id) if user_id else 'Anonyme'}: '{subject}'")
        return jsonify({"message": "Merci ! Votre feedback a été envoyé avec succès."}), 201
    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite lors de la soumission du feedback : {e}")
        return jsonify({"message": "Erreur serveur lors de l'envoi du feedback."}), 500
    except Exception as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur générale lors de la soumission du feedback : {e}")
        return jsonify({"message": "Erreur serveur inattendue."}), 500
    finally:
        if conn:
            conn.close()

# Dans app.py

@app.route('/admin/api/feedback', methods=['GET'])
def admin_get_feedback():
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, user_id, username, strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp_formatted, type, challenge_id_associated, subject, message, status FROM feedback ORDER BY CASE status WHEN 'Nouveau' THEN 1 WHEN 'En cours' THEN 2 ELSE 3 END, timestamp DESC")
        feedbacks_raw = c.fetchall()
        feedbacks_list = [dict(row) for row in feedbacks_raw] if feedbacks_raw else []
        return jsonify({"feedbacks": feedbacks_list})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite - admin_get_feedback: {e}")
        return jsonify({"message": "Erreur serveur récupération des feedbacks."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/api/feedback/update_status/<int:feedback_id>', methods=['POST'])
def admin_update_feedback_status(feedback_id):
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401

    data = request.get_json()
    new_status = data.get('status')
    valid_statuses = ['Nouveau', 'En cours', 'En attente', 'Résolu', 'Fermé', 'Rejeté'] # Statuts valides
    if not new_status or new_status not in valid_statuses:
        return jsonify({"message": "Statut invalide fourni."}), 400

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        result = c.execute("UPDATE feedback SET status = ? WHERE id = ?", (new_status, feedback_id))
        conn.commit()
        if result.rowcount > 0:
            app.logger.info(f"Statut du feedback ID {feedback_id} mis à jour à '{new_status}' par admin ID {session['admin_id']}")
            return jsonify({"message": f"Statut du feedback mis à jour à '{new_status}'."})
        else:
            return jsonify({"message": "Feedback non trouvé."}), 404
    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite - admin_update_feedback_status: {e}")
        return jsonify({"message": "Erreur serveur mise à jour statut feedback."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/api/feedback/delete/<int:feedback_id>', methods=['DELETE'])
def admin_delete_feedback(feedback_id):
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        result = c.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
        conn.commit()
        if result.rowcount > 0:
            app.logger.info(f"Feedback ID {feedback_id} supprimé par admin ID {session['admin_id']}")
            return jsonify({"message": "Feedback supprimé avec succès."})
        else:
            return jsonify({"message": "Feedback non trouvé."}), 404
    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite - admin_delete_feedback: {e}")
        return jsonify({"message": "Erreur serveur suppression feedback."}), 500
    finally:
        if conn:
            conn.close()


@app.route('/admin/challenges', methods=['GET'])
def admin_get_challenges():
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401
    
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, name, level, points, flag FROM challenges ORDER BY id DESC")
        challenges_raw = c.fetchall()
        challenges_list = [dict(row) for row in challenges_raw] if challenges_raw else []
        return jsonify({"challenges": challenges_list})
    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite - admin_get_challenges: {e}")
        return jsonify({"message": "Erreur serveur lors de la récupération des challenges."}), 500
    finally:
        if conn:
            conn.close()


@app.route('/admin/delete_challenge/<int:challenge_id>', methods=['DELETE'])
def admin_delete_challenge(challenge_id):
    if 'admin_id' not in session:
        return jsonify({"message": "Accès admin requis."}), 401
    
    app.logger.info(f"Tentative de suppression du challenge ID: {challenge_id} par l'admin ID: {session['admin_id']}")
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        c = conn.cursor()
        
        # Avant de supprimer le challenge, il faut supprimer toutes les données qui en dépendent !
        
        # 1. Trouver tous les matchs associés à ce challenge
        c.execute("SELECT id FROM matches WHERE challenge_id = ?", (challenge_id,))
        matches_to_delete = c.fetchall()
        if matches_to_delete:
            match_ids = [row[0] for row in matches_to_delete]
            # 2. Supprimer les participations des équipes à ces matchs
            c.execute(f"DELETE FROM team_matches WHERE match_id IN ({','.join('?' for _ in match_ids)})", match_ids)
            app.logger.debug(f"Suppression des team_matches pour les matchs IDs: {match_ids}")
            # 3. Supprimer les matchs eux-mêmes
            c.execute("DELETE FROM matches WHERE challenge_id = ?", (challenge_id,))
            app.logger.debug(f"Suppression des matchs pour le challenge ID: {challenge_id}")

        # 4. Supprimer les soumissions de défense liées à ce challenge
        c.execute("DELETE FROM defenses WHERE challenge_id = ?", (challenge_id,))
        app.logger.debug(f"Suppression des defenses pour le challenge ID: {challenge_id}")
        
        # 5. Supprimer les enregistrements de challenges résolus liés à ce challenge
        c.execute("DELETE FROM solved_challenges WHERE challenge_id = ?", (challenge_id,))
        app.logger.debug(f"Suppression des solved_challenges pour le challenge ID: {challenge_id}")
        
        # 6. Enfin, supprimer le challenge lui-même
        delete_result = c.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
        
        conn.commit()

        if delete_result.rowcount > 0:
            app.logger.info(f"Challenge ID: {challenge_id} et toutes ses données associées ont été supprimés.")
            return jsonify({"message": "Challenge supprimé avec succès."})
        else:
            app.logger.warning(f"Aucun challenge trouvé avec l'ID: {challenge_id} pour suppression.")
            return jsonify({"message": "Challenge non trouvé."}), 404

    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite - admin_delete_challenge: {e}")
        return jsonify({"message": "Erreur serveur lors de la suppression du challenge."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/matches', methods=['GET'])
def get_available_matches():
    if 'user_id' not in session and 'admin_id' not in session:
        return jsonify({"message": "Authentification requise."}), 401

    current_team_id = session.get('team_id')
    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # 1. Obtenir la liste de tous les matchs non terminés
        c.execute("""
            SELECT m.id, m.status, ch.name as challenge_name, ch.level, ch.points 
            FROM matches m
            JOIN challenges ch ON m.challenge_id = ch.id
            WHERE m.status IS NOT NULL AND m.status != 'terminé'
            ORDER BY m.id DESC
        """)
        matches_raw = c.fetchall()
        matches_list = [dict(row) for row in matches_raw] if matches_raw else []

        # 2. Vérifier si l'équipe de l'utilisateur est dans un match actif
        active_match_details = None
        if current_team_id:
            c.execute("""
                SELECT 
                    m.id as match_id, 
                    m.ip_address, 
                    ch.name as challenge_name,
                    tm.access_token
                FROM team_matches tm
                JOIN matches m ON tm.match_id = m.id
                JOIN challenges ch ON m.challenge_id = ch.id
                WHERE tm.team_id = ? AND m.status = 'en cours'
            """, (current_team_id,))
            active_match_raw = c.fetchone()
            if active_match_raw:
                active_match_details = dict(active_match_raw)
                # Construire l'URL Guacamole ici
                guacamole_ip = "192.168.1.100" # A rendre configurable
                active_match_details['guacamole_url'] = f"http://{guacamole_ip}/guacamole?token={active_match_details['access_token']}"

        # 3. Renvoyer les deux informations
        return jsonify({
            "available_matches": matches_list,
            "active_match": active_match_details # Sera null si l'équipe n'est dans aucun match
        })

    except sqlite3.Error as e:
        app.logger.error(f"Erreur SQLite - get_available_matches: {e}")
        return jsonify({"message": "Erreur serveur lors de la récupération des matchs."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/documentation/update/<int:article_id>', methods=['PUT'])
def admin_update_documentation(article_id):
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
            UPDATE documentation_articles 
            SET title = ?, content = ?, category = ?, tags = ?, difficulty_level = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (title, content, category, tags, difficulty_level, article_id))
        conn.commit()
        
        if c.rowcount == 0:
            return jsonify({"message": f"Aucun article avec l'ID {article_id} trouvé à mettre à jour."}), 404

        app.logger.info(f"Article de documentation ID {article_id} mis à jour.")
        return jsonify({"message": f"Article (ID: {article_id}) mis à jour avec succès !"})
    except sqlite3.Error as e:
        if conn: conn.rollback()
        return jsonify({"message": "Erreur serveur lors de la mise à jour."}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/matches/create', methods=['POST'])
def create_match():
    if 'user_id' not in session or 'team_id' not in session:
        return jsonify({"message": "Connexion et appartenance à une équipe requises."}), 401
    
    user_id = session['user_id']
    team_id = session['team_id']
    data = request.get_json()
    challenge_id = data.get('challenge_id')

    if not challenge_id:
        return jsonify({"message": "ID de challenge manquant."}), 400

    conn = None
    try:
        conn = sqlite3.connect('ctf.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("""
            SELECT tm.match_id FROM team_matches tm
            JOIN matches m ON tm.match_id = m.id
            WHERE tm.team_id = ? AND m.status = 'en cours'
        """, (team_id,))
        active_match = c.fetchone()
        if active_match:
            conn.close()
            return jsonify({"message": f"Votre équipe est déjà dans un match (ID {active_match['match_id']}). Vous ne pouvez pas en créer un nouveau."}), 400
        # --- FIN DE LA VÉRIFICATION ---

        c.execute("SELECT creator_id FROM teams WHERE id = ?", (team_id,))
        team_info = c.fetchone()
        if not team_info or team_info['creator_id'] != user_id:
            return jsonify({"message": "Seul le créateur de l'équipe peut démarrer un match."}), 403
        
        c.execute("SELECT name FROM challenges WHERE id = ?", (challenge_id,))
        if not c.fetchone():
            return jsonify({"message": "Le challenge demandé n'existe pas."}), 404

        # Placeholder pour l'intégration Proxmox
        vm_ip_address = "192.168.1.123" # IP factice
        
        status = 'en cours'
        vm_id_name = f"match_inst_{challenge_id}_{team_id}" 
        c.execute("INSERT INTO matches (challenge_id, vm_id, ip_address, status) VALUES (?, ?, ?, ?)",
                  (challenge_id, vm_id_name, vm_ip_address, status))
        new_match_id = c.lastrowid

        access_token = secrets.token_hex(16)
        c.execute("INSERT INTO team_matches (team_id, match_id, access_token) VALUES (?, ?, ?)",
                  (team_id, new_match_id, access_token))
        
        conn.commit()

        guacamole_ip = "192.168.1.100"
        return jsonify({
            "message": "Match créé et rejoint avec succès !",
            "match_id": new_match_id,
            "vm_ip": vm_ip_address,
            "access_token": access_token,
            "guacamole_url": f"http://{guacamole_ip}/guacamole?token={access_token}"
        }), 201

    except sqlite3.Error as e:
        if conn: conn.rollback()
        app.logger.error(f"Erreur SQLite - create_match: {e}")
        return jsonify({"message": "Erreur serveur lors de la création du match."}), 500
    finally:
        if conn:
            conn.close()
            
# Initialiser la base de données au démarrage
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)