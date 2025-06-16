import sys

from oprf import data, mask

from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs import Logs
from Logs.log_activity import log_activity
from Network.collections.DbConstants import VERSION


class OPRFHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)
        self.masks = {}

    @log_activity("OPRF")
    def intersection_first_step(self, device, cs):
        masked_list = []
        self.masked_points = []  # mantener orden
        for x in self.my_data:
            d = data.hash(str(x))
            m = mask.random()
            masked = m * d
            self.masks[x] = m
            self.masked_points.append((x, m, d))
            masked_list.append(masked.to_base64())
        self.send_message(device, masked_list, cs.imp_name, cs.serialize_public_key())
        return masked_list, self.masked_points

    @log_activity("OPRF")
    def intersection_second_step(self, device, cs, peer_data, pubkey):
        masked_peer_points = [data.from_base64(p) for p in peer_data]

        evaluated = [cs.get_secret() * pt for pt in masked_peer_points]
        evaluated_b64 = [pt.to_base64() for pt in evaluated]

        # Evalúa su propio conjunto también
        self_prfs = []
        for item in self.my_data:
            hashed = data.hash(str(item))
            prf_point = cs.get_secret() * hashed
            self_prfs.append(prf_point.to_base64())

        self.send_message(device, {
            "evaluated_peer": evaluated_b64,
            "server_prfs": self_prfs
        }, cs.imp_name)

        return {'oprf': evaluated_b64, 'prf_b': self_prfs}

    @log_activity("OPRF")
    def intersection_final_step(self, device, cs, peer_data):
        evaluated_peer = peer_data.get("evaluated_peer", [])
        server_prfs = peer_data.get("server_prfs", [])

        evaluated_points = [data.from_base64(p) for p in evaluated_peer]
        server_prf_set = set(server_prfs)

        intersection = []

        # recorrer los datos locales y desenmascarar
        for (x, m, hashed) in self.masked_points:
            prf_point = m.unmask(cs.get_secret() * (m * hashed))  # o directamente usar: m.unmask(eval)
            if prf_point.to_base64() in server_prf_set:
                intersection.append(x)  # x es el dato original

        print("Intersection:", intersection)
        Logs.log_result(cs.imp_name, intersection, VERSION, self.id, device)
        self.send_message(device, intersection, cs.imp_name, None)

        return intersection


