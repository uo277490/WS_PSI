import sys

from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs import Logs
from Logs.log_activity import log_activity
from Network.collections.DbConstants import VERSION


class IKNPHandler(IntersectionHandler):

    @log_activity("IKNP")
    def intersection_first_step(self, device, cs):
        m = len(self.my_data)
        t_matrix, b = cs.generate_receiver_matrix(m)
        cs.b = b

        self.send_message(device, t_matrix, cs.imp_name, cs.serialize_public_key())

        return sys.getsizeof(t_matrix), 0

    @log_activity("IKNP")
    def intersection_second_step(self, device, cs, payload, pubkey):
        t_matrix = payload
        u0, u1 = cs.compute_sender_matrices(t_matrix)
        ctxts = cs.generate_ciphertexts(self.my_data, u0, u1)

        serial_ctxts = [
            (c0.hex(), c1.hex())
            for (c0, c1) in ctxts
        ]

        payload = {
            "u0": u0,
            "u1": u1,
            "ctxts": serial_ctxts,
        }

        self.send_message(device, payload, cs.imp_name, None)

        return sys.getsizeof(u0) + sys.getsizeof(u1), 0

    @log_activity("IKNP")
    def intersection_final_step(self, device, cs, payload):
        u0 = payload["u0"]
        u1 = payload["u1"]
        hex_ctxts = payload["ctxts"]

        peer_ctxts = [
            (bytes.fromhex(h0), bytes.fromhex(h1))
            for (h0, h1) in hex_ctxts
        ]

        # 1. Derivar las claves correspondientes a mis `b` bits
        peer_keys = cs.derive_keys_from_selection(u0, u1, cs.b)

        # 2. Derivar mis propias claves a partir de los elementos de mi conjunto
        my_keys = [cs.label_to_key(x) for x in self.my_data]

        recovered = [bytes(a ^ b for a, b in zip(peer_keys[i], peer_ctxts[i][cs.b[i]]))
                     for i in range(len(peer_keys))]

        # 3. Intersección «ciega» sobre hashes / claves
        intersection = [x for x, h in zip(self.my_data, my_keys) if h in set(recovered)]

        # Registrar y enviar resultado
        print("Interseccion: ", intersection)
        self.results[device + " " + cs.imp_name] = intersection
        Logs.log_result("IKNP", intersection, VERSION, self.id, device)
        self.send_message(device, intersection, cs.imp_name, None)

        return None, None
