from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs import Logs
from Logs.log_activity import log_activity
from Network.collections.DbConstants import VERSION


class KKHandler(IntersectionHandler):
    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("KK")
    def intersection_first_step(self, device, cs):
        seeds = cs.base_ot_init(self.my_data)
        encoded = cs.encode_elements(self.my_data)
        payload = {**seeds, **encoded}
        self.send_message(device, payload, cs.imp_name, cs.serialize_public_key())
        return payload

    @log_activity("KK")
    def intersection_second_step(self, device, cs, peer_data, pubkey):
        cs.reconstruct_public_key(peer_data)

        choices = cs.compute_choices(self.my_data, peer_data)
        result = cs.extend_ot(choices)

        self.send_message(device, {'selections': result['selections']}, cs.imp_name)
        return result

    @log_activity("KK")
    def intersection_final_step(self, device, cs, peer_data):
        intersection = cs.decode_intersection(self.my_data, peer_data)

        print("Intersection: ", intersection)

        Logs.log_result(cs.imp_name, intersection, VERSION, self.id, device)
        self.send_message(device, intersection, cs.imp_name, None)

        return intersection
