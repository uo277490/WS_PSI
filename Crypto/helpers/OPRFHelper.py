from oprf import data, mask
from Crypto.helpers.CSHelper import CSHelper


class OPRFHelper(CSHelper):
    def __init__(self):
        super().__init__()
        self.imp_name = "OPRF"
        self.cs = None
        self.secret = None
        self.generate_keys()

    def encrypt(self, plaintext):
        #return self.secret.mask(plaintext)
        raise NotImplementedError("No realiza cifrado")
    def decrypt(self, ciphertext):
        #return self.secret.unmask(ciphertext)
        raise NotImplementedError("No es necesario")
    def generate_keys(self):
        self.secret = mask.random()

    def get_secret(self):
        return self.secret

    def serialize_public_key(self):
        """
        OPRF no usa clave pública real, pero este método
        es necesario para forzar que el receptor actúe como 'servidor'.
        """
        return {"fake_key": True}

    def reconstruct_public_key(self, public_key_dict):
        """OPRF no necesita reconstrucción de clave pública."""
        pass