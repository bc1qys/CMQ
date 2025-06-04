# Plateforme Pédagogique CTF - Attaque/Défense

## Description

Ce projet est une plateforme web conçue pour permettre à des étudiants (lycéens, etc.) de s'initier et de pratiquer les concepts de la cybersécurité à travers des scénarios de type "Capture The Flag" (CTF), avec une dimension Attaque/Défense. L'objectif est de fournir un environnement facile à installer, à exécuter et à utiliser dans un cadre pédagogique.

La plateforme permet aux administrateurs de créer des challenges (associés à des machines virtuelles vulnérables), de gérer les utilisateurs et les équipes. Les étudiants peuvent s'inscrire, former des équipes (avec des rôles d'attaque ou de défense), rejoindre des matchs, soumettre des flags (preuves de compromission) et des preuves de défense. Une section documentation est également intégrée pour fournir des ressources d'apprentissage.

## Fonctionnalités Principales

- **Gestion des Utilisateurs :** Inscription, connexion, scores individuels.
- **Panel Administrateur :**
  - Gestion des joueurs et des équipes (visualisation, suppression).
  - Création de challenges (nom, description, flag, points, niveau, IP de VM optionnelle).
  - Ajout d'articles de documentation.
- **Gestion des Équipes :**
  - Création d'équipes avec un rôle (Attaque/Défense).
  - Rejoindre/Quitter une équipe (avec mot de passe pour rejoindre).
  - Scores d'équipe.
- **Système de Matchs & Challenges :**
  - Les équipes peuvent rejoindre des "matchs" associés à des challenges (VMs).
  - Soumission de flags pour les équipes d'attaque.
  - Soumission de preuves de défense pour les équipes de défense.
  - Indicateur visuel (✅) pour les challenges résolus par l'équipe.
- **Section Documentation :**
  - Consultation d'articles pédagogiques sur la cybersécurité et les failles (rendu Markdown).
  - Articles avec titre, contenu, catégorie, tags, niveau de difficulté.
- **Tableau des Scores :** Classement des joueurs et des équipes.
- **Intégration VM (via Apache Guacamole) :**
  - Génération de liens d'accès aux VMs via Guacamole lors de la participation à un match.
  - (L'automatisation complète avec Proxmox pour les snapshots est une étape future envisagée).

## Stack Technique

- **Backend :** Python 3 avec Flask
- **Base de Données :** SQLite (`ctf.db`)
- **Frontend :** HTML, CSS, JavaScript (avec utilisation de la bibliothèque `marked.js` pour le rendu Markdown côté client)
- **Gestion des mots de passe :** bcrypt
- **Serveur WSGI (pour développement/déploiement local sur Windows) :** Waitress ou CherryPy
- **Serveur Web/Reverse Proxy (pour production) :** Nginx (recommandé en production devant le serveur WSGI)
- **Virtualisation (infrastructure cible) :** Proxmox VE
- **Accès VM distant via navigateur :** Apache Guacamole

## Prérequis

Avant de commencer, assurez-vous d'avoir installé :

- Python 3.8 ou supérieur
- `pip` (le gestionnaire de paquets Python)
- `virtualenv` (recommandé pour créer des environnements virtuels) :  
  ```bash
  pip install virtualenv
  ```

## Installation

1. **Cloner le dépôt (si sur GitHub) :**
   ```bash
   git clone https://github.com/bc1qys/CMQ.git
   cd CMQ
   ```

2. **Créer et activer un environnement virtuel :**  
   Il est fortement recommandé d'utiliser un environnement virtuel pour isoler les dépendances de votre projet.
   ```bash
   # Créer un environnement virtuel (par exemple, nommé "venv")
   python -m venv venv
   ```
   Activer l'environnement virtuel :
   - Sur Windows (cmd.exe) :
     ```bash
     venv\Scripts\activate.bat
     ```
   - Sur Windows (PowerShell) :
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
     (Si vous rencontrez une erreur d'exécution de script sur PowerShell, essayez `Set-ExecutionPolicy Unrestricted -Scope Process` puis réessayez d'activer).
   - Sur Linux ou macOS :
     ```bash
     source venv/bin/activate
     ```
   Votre invite de commande devrait maintenant être préfixée par `(venv)`.

3. **Installer les dépendances :**  
   Une fois l'environnement virtuel activé, installez les paquets Python nécessaires listés dans `requirements.txt` :
   ```bash
   pip install -r requirements.txt
   ```
   *Si le fichier `requirements.txt` n'est pas encore créé, vous pouvez le générer depuis votre environnement virtuel actuel (où vous avez installé Flask, bcrypt, etc.) avec :*
   ```bash
   pip freeze > requirements.txt
   ```
   *Assurez-vous que `Flask`, `bcrypt`, et `waitress` ou `CherryPy` (selon votre choix pour Windows) sont dans ce fichier.*

4. **Initialisation de la base de données :**  
   La base de données SQLite (`ctf.db`) et ses tables (y compris le compte admin par défaut) sont créées automatiquement au premier lancement de l'application Flask (`app.py`) grâce à la fonction `init_db()` appelée via `with app.app_context(): init_db()`.

## Configuration

- **Clé Secrète Flask :**  
  La clé secrète de l'application Flask (`app.secret_key`) est actuellement générée de manière aléatoire à chaque lancement dans `app.py` (`secrets.token_hex(16)`). Pour un déploiement stable (où les sessions utilisateurs persistent entre les redémarrages du serveur), il est recommandé de définir une clé secrète fixe, idéalement via une variable d'environnement (par exemple, `FLASK_SECRET_KEY`).
- **URL Guacamole :**  
  L'URL du serveur Guacamole est actuellement codée en dur dans `app.py` dans la fonction `join_match` (ex: `http://192.168.1.100/guacamole...`). Pour un déploiement réel, rendez cette URL configurable (par exemple, via une variable d'environnement dans votre `app.py` ou un fichier de configuration).

## Exécution de l'Application

Choisissez l'une des méthodes suivantes pour lancer l'application :

### 1. Avec le serveur de développement Flask (pour le développement uniquement)

Si le bloc suivant est présent et non commenté dans `app.py` (ce qui est le cas dans votre fichier `app.py` actuel) :
```python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```
Lancez :
```bash
python app.py
```
L'application sera accessible sur [http://localhost:5000](http://localhost:5000) (ou [http://<votre_ip_locale>:5000](http://<votre_ip_locale>:5000) si `host='0.0.0.0'` est utilisé). Le mode `debug=True` sera activé.

### 2. Avec Waitress (Recommandé pour Windows)

Assurez-vous que Waitress est listé dans `requirements.txt` et installé :
```bash
pip install waitress
```
Créez un fichier `run_waitress.py` à la racine de votre projet :
```python
from waitress import serve
from app import app  # Assurez-vous que votre instance Flask est nommée 'app' dans app.py

if __name__ == '__main__':
    host = '0.0.0.0'
    port = 8000  # Ou le port de votre choix
    print(f"Serveur Waitress démarré sur http://{host}:{port}")
    serve(app, host=host, port=port)
```
Lancez le serveur :
```bash
python run_waitress.py
```
L'application sera accessible sur [http://localhost:8000](http://localhost:8000) (ou l'adresse IP de votre machine sur le port spécifié).

### 3. Avec CherryPy (Alternative pour Windows)

Assurez-vous que CherryPy (et sa dépendance Cheroot) sont listés dans `requirements.txt` et installés :
```bash
pip install CherryPy
```
Créez un fichier `run_cherrypy.py` à la racine de votre projet :
```python
from cheroot.wsgi import Server as CherootWSGIServer
from cheroot.wsgi import PathInfoDispatcher
from app import app  # Assurez-vous que votre instance Flask est nommée 'app' dans app.py

if __name__ == '__main__':
    dispatcher = PathInfoDispatcher({'/': app})
    server = CherootWSGIServer(
        ('0.0.0.0', 8080),  # Ou le port de votre choix
        dispatcher
    )
    actual_host, actual_port = server.bind_addr
    print(f"Serveur Cheroot (pour CherryPy) démarré sur http://{actual_host}:{actual_port}")
    print("Appuyez sur Ctrl+C pour arrêter le serveur.")
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nArrêt du serveur Cheroot.")
        server.stop()
    except Exception as e:
        print(f\"Une erreur est survenue avec le serveur Cheroot: {e}\")
        if server:
            server.stop()
```
Lancez le serveur :
```bash
python run_cherrypy.py
```
L'application sera accessible sur [http://localhost:8080](http://localhost:8080).

### Remarque sur Gunicorn (pour déploiement Linux)

Si vous déployez sur un serveur Linux, Gunicorn est une option très courante :
```bash
# Exemple de commande Gunicorn (à adapter)
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```
Ceci nécessite que Gunicorn soit installé :
```bash
pip install gunicorn
```

## Utilisation

### Accès Admin

Naviguez vers `/login` et connectez-vous avec les identifiants admin par défaut (créés lors de l'initialisation de la base de données si `INSERT OR IGNORE` a fonctionné) :

- **Nom d'utilisateur :** `admin`
- **Mot de passe :** `admin`

Vous serez redirigé vers le panel `/admin` où vous pourrez gérer les joueurs, les équipes, les challenges et la documentation.

### Accès Utilisateur

Les utilisateurs peuvent s'inscrire via la page `/login`.  
Une fois connectés, ils accèdent à `home.html` (la racine `/`) où ils peuvent :

- Consulter leur profil et leur score.
- Voir le tableau des scores général.
- Parcourir la liste des challenges (avec indicateur des challenges résolus par leur équipe ✅).
- Accéder à la section "Base de Connaissances" pour lire la documentation (articles en Markdown rendus en HTML).
- Créer une équipe (en spécifiant un rôle Attaque/Défense et un mot de passe).
- Rejoindre une équipe existante (en fournissant l'ID de l'équipe et son mot de passe).
- Quitter leur équipe.
- Rejoindre un match (si créateur de l'équipe).
- Soumettre des flags pour les challenges (si équipe d'attaque et dans un match actif pour le challenge).
- Soumettre des preuves de défense.
- Quitter un match.

## Intégration des Machines Virtuelles (VMs)

La plateforme est conçue pour interagir avec des VMs de challenge, qui seraient idéalement hébergées sur un serveur Proxmox.  
L'accès aux VMs par les utilisateurs se fait via des liens Apache Guacamole générés par l'application lorsqu'une équipe rejoint un match.

- **Phase actuelle :**  
  La génération de liens est implémentée dans la logique de `join_match`. Le serveur Guacamole et les VMs Proxmox doivent être configurés séparément. L'URL de Guacamole est actuellement en dur et devrait être rendue configurable.

- **Évolutions futures envisagées :**
  - Intégration d'une API pour communiquer avec Proxmox afin d'automatiser la réinitialisation des VMs à leur snapshot de base après un match ou avant une nouvelle session.
  - Gestion plus dynamique du cycle de vie des VMs (démarrage, arrêt, clonage pour des scénarios A/D plus complexes) directement depuis la plateforme.

## Structure du Projet (Simplifiée)

```
.
├── app.py                # Application Flask principale (backend, routes API, logique métier)
├── requirements.txt      # Dépendances Python nécessaires au projet
├── ctf.db                # Base de données SQLite (créée au premier lancement)
├── run_waitress.py       # (Optionnel) Script pour lancer avec Waitress sous Windows
├── run_cherrypy.py       # (Optionnel) Script pour lancer avec CherryPy sous Windows
├── templates/
│   ├── admin.html        # Interface du panel d'administration
│   ├── home.html         # Tableau de bord principal pour les utilisateurs connectés
│   ├── index.html        # Page de test initiale (pourrait être supprimée ou réutilisée)
│   └── login.html        # Page de connexion et d'inscription des utilisateurs
└── static/               # (Optionnel, si vous avez des fichiers CSS/JS/images globaux non gérés par Flask)
    └── ...
```

## Contributions

Ce projet est développé dans un cadre de stage. Les suggestions et contributions pour améliorer la plateforme sont les bienvenues.