import unittest
from Crypto.helpers.IKNPHelper import IKNPHelper


def test_generate_receiver_matrix():
    helper = IKNPHelper(k=16)
    m = 5
    t, b = helper.generate_receiver_matrix(m)

    assert isinstance(t, list) and len(t) == helper.k
    assert all(isinstance(col, list) and len(col) == m for col in t)
    # b debe tener longitud m y contener sólo {0,1}
    assert isinstance(b, list) and len(b) == m
    assert set(b) <= {0,1}


def test_compute_sender_matrices():
    helper = IKNPHelper(k=8)
    m = 3
    t, _ = helper.generate_receiver_matrix(m)
    u0, u1 = helper.compute_sender_matrices(t)
    # u0 y u1 deben ser listas de m vectores de k bits
    assert isinstance(u0, list) and isinstance(u1, list)
    assert len(u0) == m and len(u1) == m
    assert all(len(vec) == helper.k for vec in u0)
    # Para cada i: u0[i] XOR u1[i] == delta
    delta_row = helper.delta.tolist()
    for v0, v1 in zip(u0, u1):
        xor01 = [x ^ y for x, y in zip(v0, v1)]
        assert xor01 == delta_row


def test_derive_keys_from_selection():
    helper = IKNPHelper(k=8)
    m = 4
    t, b = helper.generate_receiver_matrix(m)
    u0, u1 = helper.compute_sender_matrices(t)
    keys = helper.derive_keys_from_selection(u0, u1, b)
    # Debe devolver m claves SHA256 (32 bytes cada una)
    assert isinstance(keys, list) and len(keys) == m
    assert all(isinstance(k, bytes) and len(k) == 32 for k in keys)
    # Las claves deben diferir al menos en algunos índices (no todas iguales)
    assert len(set(keys)) > 1


def test_generate_recover_ciphertexts():
    helper = IKNPHelper(k=16)
    data = [b"alice", b"bob", b"carol"]
    # Paso R1/R2
    t, b = helper.generate_receiver_matrix(len(data))
    # Paso S2
    u0, u1 = helper.compute_sender_matrices(t)
    ctxts = helper.generate_ciphertexts(data, u0, u1)
    # Paso R3
    keys = helper.derive_keys_from_selection(u0, u1, b)
    # Recuperación: para cada i, C_b[i] XOR key[i] == SHA256(data[i])
    for i, item in enumerate(data):
        l = helper.label_to_key(item)
        c0, c1 = ctxts[i]
        cb = c0 if b[i] == 0 else c1
        recovered = bytes(a ^ b for a, b in zip(keys[i], cb))
        assert recovered == l


def test_label_to_key():
    helper = IKNPHelper()
    x = "hello"
    h1 = helper.label_to_key(x)
    h2 = helper.label_to_key(x.encode())
    # Debe ser determinista e idéntico para str/bytes
    assert h1 == h2


def test_full_intersection():
    helper = IKNPHelper(k=32)
    # Conjunto emisor A y receptor B con intersección {2,4}
    A = [1,2,3,4,5]
    B = [2,4,6,8,10]
    # R1/R2
    t, b = helper.generate_receiver_matrix(len(B))
    # S2
    u0, u1 = helper.compute_sender_matrices(t)
    ctxts = helper.generate_ciphertexts(A, u0, u1)
    # R3
    keys_B = helper.derive_keys_from_selection(u0, u1, b)
    # Receptor descifra hashes de A∩B
    recovered_hashes = [
        bytes(a ^ b for a, b in zip(keys_B[i],
                                    ctxts[i][b[i]]))
        for i in range(len(B))
    ]
    # Calcula etiquetas de B
    hashes_B = [helper.label_to_key(x) for x in B]
    # Sólo deben coincidir los de intersección
    common = {h for h in recovered_hashes if h in hashes_B}
    # Mapear hashes de vuelta a valores
    inv = {helper.label_to_key(x): x for x in A}
    intersection = sorted(inv[h] for h in common)
    assert intersection == [2, 4]


if __name__ == "__main__":
    unittest.main()
