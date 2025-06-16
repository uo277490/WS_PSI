import hashlib
import os
from Crypto.helpers.CSHelper import CSHelper


class KKHelper(CSHelper):

    def __init__(self, kappa=128):
        super().__init__()
        self.imp_name = "KK"
        self.kappa = kappa
        self._seed0 = []
        self._seed1 = []
        self._pairs = []

    def serialize_public_key(self):
        return {"fake_key": True}

    def base_ot_init(self, _):
        # Generate 2*kappa random seeds
        self._seed0 = [os.urandom(self.kappa // 8) for _ in range(self.kappa)]
        self._seed1 = [os.urandom(self.kappa // 8) for _ in range(self.kappa)]
        return {'seed0': [s.hex() for s in self._seed0],
                'seed1': [s.hex() for s in self._seed1]}

    def reconstruct_public_key(self, pub):
        # Load seed pairs
        self._seed0 = [bytes.fromhex(h) for h in pub['seed0']]
        self._seed1 = [bytes.fromhex(h) for h in pub['seed1']]

    def extend_ot(self, choices):
        # Derive selection bits t_j on chosen seeds
        n = len(choices)
        seeds = [self._seed1[i] if choices[i] else self._seed0[i]
                 for i in range(min(self.kappa, n))]
        t = [0] * n
        for seed in seeds:
            for j in range(n):
                h = hashlib.sha256(seed + j.to_bytes(4, 'big')).digest()
                t[j] ^= (h[0] & 1)
        return {'selections': t}

    def encode_elements(self, elements):
        # Encode each element into two ciphertexts c0,c1
        self._pairs = []
        e0_list, e1_list = [], []
        for j, x in enumerate(elements):
            hashes = hashlib.sha256(str(x).encode()).digest()
            byte_list1 = bytearray(len(hashes))
            byte_list2 = bytearray(len(hashes))
            for seed in self._seed0:
                prg = hashlib.sha256(seed + j.to_bytes(4, 'big')).digest()
                for idx in range(len(hashes)): byte_list1[idx] ^= prg[idx]
            for seed in self._seed1:
                prg = hashlib.sha256(seed + j.to_bytes(4, 'big')).digest()
                for idx in range(len(hashes)): byte_list2[idx] ^= prg[idx]
            c0 = bytes(a ^ b for a, b in zip(hashes, byte_list1))
            c1 = bytes(a ^ b for a, b in zip(hashes, byte_list2))
            self._pairs.append((c0, c1))
            e0_list.append(c0.hex())
            e1_list.append(c1.hex())
        return {'e0': e0_list, 'e1': e1_list}

    def compute_choices(self, my_elements, payload):
        # Receiver: compute choice bits by attempting decrypt on encoded pairs
        e0 = payload.get('e0', [])
        e1 = payload.get('e1', [])
        # precompute hashes of receiver elements
        hash_set = {hashlib.sha256(str(x).encode()).digest(): None for x in my_elements}
        n = len(e0)
        choices = [0] * n
        # for each ciphertext pair, test membership
        for j in range(n):
            c0 = bytes.fromhex(e0[j])
            c1 = bytes.fromhex(e1[j])
            # rebuild masks
            h_mask0 = bytearray(len(c0))
            h_mask1 = bytearray(len(c1))
            for seed in self._seed0:
                prg = hashlib.sha256(seed + j.to_bytes(4, 'big')).digest()
                for idx in range(len(prg)): h_mask0[idx] ^= prg[idx]
            for seed in self._seed1:
                prg = hashlib.sha256(seed + j.to_bytes(4, 'big')).digest()
                for idx in range(len(prg)): h_mask1[idx] ^= prg[idx]
            # decrypt
            rec0 = bytes(a ^ b for a, b in zip(c0, h_mask0))
            rec1 = bytes(a ^ b for a, b in zip(c1, h_mask1))
            # choose bit if matches any
            if rec1 in hash_set:
                choices[j] = 1
            elif rec0 in hash_set:
                choices[j] = 0
            else:
                choices[j] = 0
        return choices

    def decode_intersection(self, elements, peer_data):
        # Sender: decode final intersection using selections
        selections = peer_data.get('selections', [])
        intersection = []
        for j, x in enumerate(elements):
            t_j = selections[j]
            c0, c1 = self._pairs[j]
            hashes = hashlib.sha256(str(x).encode()).digest()
            # rebuild mask
            mask = bytearray(len(hashes))
            for seed in (self._seed0 if t_j == 0 else self._seed1):
                prg = hashlib.sha256(seed + j.to_bytes(4, 'big')).digest()
                for idx in range(len(prg)): mask[idx] ^= prg[idx]
            c_b = c0 if t_j == 0 else c1
            rec = bytes(a ^ b for a, b in zip(c_b, mask))
            if rec == hashes:
                intersection.append(x)
        return intersection
