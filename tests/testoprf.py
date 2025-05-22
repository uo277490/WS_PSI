
import unittest
from oprf import data, mask

from Crypto.helpers.OPRFHelper import OPRFHelper


class TestOPRFProtocol(unittest.TestCase):
    def setUp(self):
        # Inicializamos dos instancias de helper: cliente y servidor
        self.client = OPRFHelper()
        self.server = OPRFHelper()
        # Generar clave secreta sólo en el servidor
        self.server.generate_keys()

    def test_basic_intersection(self):
        # Definimos dos conjuntos con intersección parcial
        A = ["alice", "bob", "charlie"]
        B = ["bob", "david", "eve"]

        # Fase 1: cliente enmascara sus elementos
        client_masks = {}
        client_masked_b64 = []
        for x in A:
            P = data.hash(x)
            m = mask.random()
            client_masks[x] = m
            client_masked_b64.append((m * P).to_base64())

        # Fase 2: servidor evalúa los puntos enmascarados y calcula sus propios PRF
        server_evaluated_b64 = []
        for mP_b64 in client_masked_b64:
            mP = data.from_base64(mP_b64)
            evaluated = self.server.get_secret() * mP
            server_evaluated_b64.append(evaluated.to_base64())

        server_prf_b_b64 = []
        for y in B:
            Q = data.hash(y)
            prf_b = self.server.get_secret() * Q
            server_prf_b_b64.append(prf_b.to_base64())

        # Fase 3: cliente desenmascara y calcula intersección
        prf_a = {}
        for i, x in enumerate(A):
            evaluated_b64 = server_evaluated_b64[i]
            evaluated = data.from_base64(evaluated_b64)
            unmasked = client_masks[x].unmask(evaluated)
            prf_a[x] = unmasked.to_base64()

        # Intersección: aquellos x ∈ A tales que prf_a[x] coincide con algún prf_b
        expected = ["bob"]
        result = [x for x, v in prf_a.items() if v in server_prf_b_b64]

        self.assertListEqual(sorted(result), sorted(expected),
                             f"Se esperaba intersección {expected}, se obtuvo {result}")

    def test_empty_intersection(self):
        # Conjuntos sin elementos comunes
        A = ["alice", "bob"]
        B = ["charlie", "david"]

        # Fase 1
        client_masks = {}
        client_masked_b64 = []
        for x in A:
            P = data.hash(x)
            m = mask.random()
            client_masks[x] = m
            client_masked_b64.append((m * P).to_base64())

        # Fase 2
        server_evaluated_b64 = []
        for mP_b64 in client_masked_b64:
            mP = data.from_base64(mP_b64)
            evaluated = self.server.get_secret() * mP
            server_evaluated_b64.append(evaluated.to_base64())

        server_prf_b_b64 = []
        for y in B:
            Q = data.hash(y)
            prf_b = self.server.get_secret() * Q
            server_prf_b_b64.append(prf_b.to_base64())

        # Fase 3
        prf_a = {}
        for i, x in enumerate(A):
            evaluated_b64 = server_evaluated_b64[i]
            evaluated = data.from_base64(evaluated_b64)
            unmasked = client_masks[x].unmask(evaluated)
            prf_a[x] = unmasked.to_base64()

        result = [x for x, v in prf_a.items() if v in server_prf_b_b64]
        self.assertListEqual(result, [],
                             f"Se esperaba intersección vacía, se obtuvo {result}")

if __name__ == "__main__":
    unittest.main()
