import secrets
import hashlib
from typing import Sequence

import numpy as np
from Crypto.helpers.CSHelper import CSHelper


class IKNPHelper(CSHelper):
    def __init__(self, k: int = 128):
        super().__init__()
        self.k = k
        self.delta: np.ndarray = self._random_bits(k)  # sender's Δ
        self.b: np.ndarray | None = None  #
        self.t_matrix: np.ndarray | None = None
        self.imp_name = "IKNP"

    def serialize_public_key(self):
        return {"fake_key": True}

    def reconstruct_public_key(self, public_key_dict):
        self.delta = np.array(public_key_dict["delta"], dtype=np.uint8)

    def generate_receiver_matrix(self, m: int) -> tuple[list[list[int]], list[int]]:
        self.b = self._random_bits(m)
        self.t_matrix = self._random_bits(self.k * m).reshape((self.k, m))
        return self.t_matrix.tolist(), self.b.tolist()

    def derive_keys_from_selection(
        self,
        u0: Sequence[Sequence[int]],
        u1: Sequence[Sequence[int]],
        b: Sequence[int] | None = None,
    ) -> list[bytes]:
        if b is None:
            if self.b is None:
                raise ValueError("Selection vector b missing")
            b = self.b
        if len(u0) != len(b):
            raise ValueError("Inconsistent lengths between u‑matrices and b")

        keys: list[bytes] = []
        for i, bit in enumerate(b):
            row = u0[i] if bit == 0 else u1[i]
            keys.append(self.derive_key(row))
        return keys

    def generate_ciphertexts(self, data, u0, u1):
        ctxts = []
        for i, y in enumerate(data):
            key0 = self.derive_key(u0[i])
            key1 = self.derive_key(u1[i])
            label = self.label_to_key(y)
            c0 = bytes(a ^ b for a, b in zip(key0, label))
            c1 = bytes(a ^ b for a, b in zip(key1, label))
            ctxts.append((c0, c1))
        return ctxts

    def compute_sender_matrices(self, t_matrix_list: Sequence):
        t_matrix = np.array(t_matrix_list, dtype=np.uint8)
        m = t_matrix.shape[1]

        v_matrix = t_matrix.T
        delta_row = np.tile(self.delta, (m, 1))

        u0 = v_matrix
        u1 = np.bitwise_xor(v_matrix, delta_row)

        return u0.tolist(), u1.tolist()

    @staticmethod
    def derive_key(bits: Sequence[int]) -> bytes:
        vec = np.array(bits, dtype=np.uint8)
        packed = np.packbits(vec, bitorder="big").tobytes()
        return hashlib.sha256(packed).digest()

    @staticmethod
    def label_to_key(label: int | bytes | str) -> bytes:
        if isinstance(label, bytes):
            data = label
        else:
            data = str(label).encode()
        return hashlib.sha256(data).digest()


    @staticmethod
    def _random_bits(n: int) -> np.ndarray:
        """Return *n* unbiased random bits as *uint8* NumPy array."""
        n_bytes = (n + 7) // 8
        random_bytes = secrets.token_bytes(n_bytes)
        bits = np.unpackbits(
            np.frombuffer(random_bytes, dtype=np.uint8), bitorder="big"
        )
        return bits[:n].astype(np.uint8)

    def encrypt(self, plaintext):  # type: ignore[override]
        return plaintext

    def decrypt(self, ciphertext):  # type: ignore[override]
        return ciphertext

    def generate_keys(self, *_, **__):  # type: ignore[override]
        pass  # not required for IKNP extension

    def get_ciphertext(self, encrypted_number):
        return encrypted_number

    def encrypt_my_data(self, my_set, domain):
        return my_set

    def horner_encrypted_eval(self, coeffs, x):
        pass

    def intersection_enc_size(self, multiplied_set):
        pass

    def get_evaluations(self, coeffs, pubkey, my_data):
        pass

    def serialize_result(self, result, type):
        return result
