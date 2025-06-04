# Plateforme Pédagogique CTF - Attaque/Défense

## Description

Ce projet est une plateforme web conçue pour permettre à des étudiants (lycéens, etc.) de s'initier et de pratiquer les concepts de la cybersécurité à travers des scénarios de type "Capture The Flag" (CTF), avec une dimension Attaque/Défense. L'objectif est de fournir un environnement facile à installer, à exécuter et à utiliser dans un cadre pédagogique.

La plateforme permet aux administrateurs de créer des challenges (associés à des machines virtuelles vulnérables), de gérer les utilisateurs et les équipes. Les étudiants peuvent s'inscrire, former des équipes (avec des rôles d'attaque ou de défense), rejoindre des matchs, soumettre des flags (preuves de compromission) et des preuves de défense. Une section documentation est également intégrée pour fournir des ressources d'apprentissage.

## Fonctionnalités Principales

* **Gestion des Utilisateurs :** Inscription, connexion, scores individuels.
* **Panel Administrateur :**
    * Gestion des joueurs et des équipes (visualisation, suppression).
    * Création de challenges (nom, description, flag, points, niveau, IP de VM optionnelle).
    * Ajout d'articles de documentation.
* **Gestion des Équipes :**
    * Création d'équipes avec un rôle (Attaque/Défense).
    * Rejoindre/Quitter une équipe (avec mot de passe pour rejoindre).
    * Scores d'équipe.
* **Système de Matchs & Challenges :**
    * Les équipes peuvent rejoindre des "matchs" associés à des challenges (VMs).
    * Soumission de flags pour les équipes d'attaque.
    * Soumission de preuves de défense pour les équipes de défense.
* **Section Documentation :**
    * Consultation d'articles pédagogiques sur la cybersécurité et les failles.
    * Articles avec titre, contenu (Markdown), catégorie, tags, niveau de difficulté.
* **Tableau des Scores :** Classement des joueurs et des équipes.
* **Intégration VM (via Apache Guacamole) :**
    * Génération de liens d'accès aux VMs via Guacamole lors de la participation à un match.
    * (L'automatisation complète avec Proxmox pour les snapshots est une étape future envisagée).

## Stack Technique

* **Backend :** Python 3 avec Flask
* **Base de Données :** SQLite (`ctf.db`)
* **Frontend :** HTML, CSS, JavaScript
* **Gestion des mots de passe :** bcrypt
* **Serveur WSGI (pour développement/déploiement local sur Windows) :** Waitress ou CherryPy (recommandé à la place de Gunicorn qui est pour Unix)
* **Serveur Web/Reverse Proxy (pour production) :** Nginx (recommandé en production devant le serveur WSGI)
* **Virtualisation (infrastructure cible) :** Proxmox VE
* **Accès VM distant via navigateur :** Apache Guacamole

## Prérequis

Avant de commencer, assurez-vous d'avoir installé :

* Python 3.8 ou supérieur
* `pip` (le gestionnaire de paquets Python)
* `virtualenv` (recommandé pour créer des environnements virtuels) : `pip install virtualenv`

## Installation

1.  **Cloner le dépôt (si sur GitHub) :**
    ```bash
    git clone <URL_DE_VOTRE_DEPOT_GITHUB>
    cd <NOM_DU_DOSSIER_DU_PROJET>
    ```

2.  **Créer et activer un environnement virtuel :**
    Il est fortement recommandé d'utiliser un environnement virtuel pour isoler les dépendances de votre projet.
    ```bash
    # Créer un environnement virtuel (par exemple, nommé "venv")
    python -m venv venv
    ```
    Activer l'environnement virtuel :
    * Sur Windows (cmd.exe) :
        ```bash
        venv\Scripts\activate.bat
        ```
    * Sur Windows (PowerShell) :
        ```ps1
        .\venv\Scripts\Activate.ps1
        ```
        (Si vous rencontrez une erreur d'exécution de script sur PowerShell, essayez `Set-ExecutionPolicy Unrestricted -Scope Process` puis réessayez d'activer).
    * Sur Linux ou macOS :
        ```bash
        source venv/bin/activate
        ```
    Votre invite de commande devrait maintenant être préfixée par `(venv)`.

3.  **Installer les dépendances :**
    Une fois l'environnement virtuel activé, installez les paquets Python nécessaires listés dans `requirements.txt` :
    ```bash
    pip install -r requirements.txt
    ```
    *Si le fichier `requirements.txt` n'est pas encore créé, vous pouvez le générer depuis votre environnement virtuel actuel (où vous avez installé Flask, bcrypt, etc.) avec :*
    ```bash
    pip freeze > requirements.txt
    ```
    *Assurez-vous que `Flask`, `bcrypt`, et potentiellement `waitress` ou `CherryPy` (selon votre choix de serveur pour Windows) sont dans ce fichier.*

4.  **Initialisation de la base de données :**
    La base de données SQLite (`ctf.db`) et ses tables (y compris les comptes admin par défaut et les tables de documentation/challenges résolus) sont créées automatiquement au premier lancement de l'application Flask (`app.py`) grâce à la fonction `init_db()` appelée via `with app.app_context(): init_db()`.

## Configuration

* **Clé Secrète Flask :** La clé secrète de l'application Flask (`app.secret_key`) est actuellement générée de manière aléatoire à chaque lancement dans `app.py` (`secrets.token_hex(16)`). Pour un déploiement plus stable (où les sessions utilisateurs persistent entre les redémarrages du serveur), il est recommandé de définir une clé secrète fixe, idéalement via une variable d'environnement.
* **URL Guacamole :** L'URL du serveur Guacamole est actuellement codée en dur dans `app.py` dans la fonction `join_match`. Pour un déploiement réel, rendez cette URL configurable (par exemple, via une variable d'environnement ou un fichier de configuration).

## Exécution de l'Application

Choisissez l'une des méthodes suivantes pour lancer l'application :

**1. Avec le serveur de développement Flask (pour le développement uniquement) :**
   Le fichier `app.py` contient le bloc :
   ```python
   if __name__ == '__main__':
       app.run(host='0.0.0.0', port=5000, debug=True)