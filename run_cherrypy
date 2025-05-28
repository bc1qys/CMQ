from cheroot.wsgi import Server as CherootWSGIServer
from cheroot.wsgi import PathInfoDispatcher
from app import app  # Assurez-vous que votre instance Flask est bien nommée 'app' dans app.py

if __name__ == '__main__':
    # Crée un dispatcher pour votre application WSGI Flask
    # '/' signifie que l'application Flask gérera toutes les routes à partir de la racine
    dispatcher = PathInfoDispatcher({'/': app})

    # Crée une instance du serveur WSGI Cheroot
    # Remplacez '0.0.0.0' et 8080 par l'hôte et le port que vous souhaitez utiliser
    server = CherootWSGIServer(
        ('0.0.0.0', 8080),  # Écoute sur toutes les interfaces, port 8080
        dispatcher
    )

    # Options de configuration supplémentaires pour Cheroot (facultatif) :
    # server.thread_pool = 30  # Nombre de threads dans le pool de threads
    # server.accepted_queue_size = 100 # Taille de la file d'attente des connexions acceptées
    # server.max_request_header_size = 1024 * 128 # 128KB
    # server.max_request_body_size = 1024 * 1024 * 10 # 10MB

    # Récupérer l'hôte et le port réels sur lesquels le serveur écoute (utile si le port 0 est utilisé pour un port aléatoire)
    actual_host, actual_port = server.bind_addr
    print(f"Serveur Cheroot (utilisé par CherryPy) démarré sur http://{actual_host}:{actual_port}")
    print("Appuyez sur Ctrl+C pour arrêter le serveur.")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nArrêt du serveur Cheroot en cours...")
        server.stop()
        print("Serveur arrêté.")
    except Exception as e:
        print(f"Une erreur est survenue avec le serveur Cheroot: {e}")
        if server: # S'assurer que l'objet serveur existe avant d'appeler stop
            server.stop()
            print("Serveur arrêté suite à une erreur.")