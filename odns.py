from ecies.utils import generate_key
from ecies import encrypt as ECIESencrypt
from ecies import decrypt as ECIESdecrypt
# from coincurve import PublicKey

class ODNSCypher():
    """
        Holding all cryptography informations (keys, nonces, algorithms) to
        decypher requests and cypher back replies.

        Using ECIES algorithm
    """

    def __init__(self, sk=None):
        """
            sk  - Private (secret) Key of the proxy
        """

        self.sk = sk
        self.pk = None

        if not self.sk:
            print("No secret key given. Generating a new one...")
            self.generate_key_pair()

    def generate_key_pair(self):
        secp_k = generate_key()
        self.sk = secp_k.secret
        self.pk = secp_k.public_key.format(True)
        print("New pk : ", self.pk.hex())

    def decrypt(self, name):
        """
            name - data to decrypt
        """
        return ECIESdecrypt(self.sk, name)

    def encrypt(self, name, original_request):
        """
            name              - data to encrypt
            original_request  - request made by client. Containing its public key
        """
        # Extract the sender key from the request
        sender_pk = original_request[:65]
        return ECIESencrypt(sender_pk, name)
