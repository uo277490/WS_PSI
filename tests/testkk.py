import unittest
from Crypto.helpers.KKHelper import KKHelper


class TestKKOTAdditional(unittest.TestCase):
    def setUp(self):
        self.kappa = 8
        self.sender = KKHelper(self.kappa)
        self.receiver = KKHelper(self.kappa)
        self.sender_set = ['apple', 'banana', 'cherry', 'date']
        self.disjoint_set = ['fig', 'grape']

    def test_extend_ot_variation(self):
        # Semillas compartidas
        seeds = self.sender.base_ot_init(None)
        self.receiver.reconstruct_public_key(seeds)
        # Dos vectores de choices distintos
        choices1 = [0, 1, 0, 1]
        choices2 = [1, 0, 1, 0]
        sel1 = self.receiver.extend_ot(choices1)['selections']
        sel2 = self.receiver.extend_ot(choices2)['selections']
        # Deben ser diferentes (muy improbable colisión)
        self.assertNotEqual(sel1, sel2)

    def test_compute_choices_full_and_empty(self):
        # Preparar flujo base
        seeds = self.sender.base_ot_init(None)
        self.receiver.reconstruct_public_key(seeds)
        encoded = self.sender.encode_elements(self.sender_set)
        # Caso full
        choices_full = self.receiver.compute_choices(self.sender_set, encoded)
        self.assertEqual(choices_full, [1] * len(self.sender_set))
        # Caso empty
        choices_empty = self.receiver.compute_choices(self.disjoint_set, encoded)
        # length = len(sender_set), y todos 0
        self.assertEqual(choices_empty, [0] * len(self.sender_set))

    def test_full_protocol_consistency(self):
        # Recorrido completo para sets idénticos
        seeds = self.sender.base_ot_init(None)
        self.receiver.reconstruct_public_key(seeds)
        encoded = self.sender.encode_elements(self.sender_set)
        choices = self.receiver.compute_choices(self.sender_set, encoded)
        selections = self.receiver.extend_ot(choices)['selections']
        inter = self.sender.decode_intersection(self.sender_set, {'selections': selections})
        self.assertEqual(set(inter), set(self.sender_set))


if __name__ == '__main__':
    unittest.main()
