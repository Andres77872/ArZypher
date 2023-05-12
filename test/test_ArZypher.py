import unittest
import time
from ArZypher import arzypher_decoder, arzypher_encoder
from ArZypher.ArZypher import (
    pad
)

PRIVATE_KEY = 'rule the world'


class MyTestCase(unittest.TestCase):
    def test_arzypher_encoder_void(self):
        pkey = []
        inp = []
        check_sum = None
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        self.assertEqual('', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_001(self):
        pkey = [8]
        inp = [8]
        check_sum = None
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('CA==', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_002(self):
        pkey = [2]
        inp = [3]
        check_sum = None
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('Aw==', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_003(self):
        pkey = [2]
        inp = [4]
        check_sum = None
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        self.assertEqual(b64, '')
        self.assertEqual(key, None)

    def test_arzypher_encoder_004(self):
        pkey = [2, 2, 2, 2]
        inp = [3, 3, 2, 1]
        check_sum = None
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('_Q==', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_005(self):
        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=None,
            check_sum=None,
            params_keys=[2, 2, 2],
            params_data=[3, 4, 2],
            padding=None
        )
        self.assertEqual('', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_006(self):
        pkey = [2, 2, 2]
        inp = [3, 3, 2]
        check_sum = 10
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('uv4=', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_007(self):
        pkey = [2, 2, 2]
        inp = [3, 3, 2]
        check_sum = 256
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )
        self.assertEqual('uva2S_c_dV001JqMgpwZztzbcBEAKqCjcxsj-GuYHWo_', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_008(self):
        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=None,
            check_sum=257,
            params_keys=[2, 2, 2],
            params_data=[3, 3, 2],
            padding=None
        )
        self.assertEqual('', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_009(self):
        pkey = [2, 2, 2]
        inp = [3, 3, 2]
        check_sum = 0
        random_key = None

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )
        self.assertEqual('Pg==', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_010(self):
        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=None,
            check_sum=-1,
            params_keys=[2, 2, 2],
            params_data=[3, 3, 2],
            padding=None
        )
        self.assertEqual('', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_011(self):
        pkey = [2, 2, 2]
        inp = [3, 3, 2]
        check_sum = 10
        random_key = 16

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertNotEqual(None, key)

    def test_arzypher_encoder_012(self):
        pkey = [2, 2, 2]
        inp = [3, 3, 2]
        check_sum = 26
        random_key = 16

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertNotEqual(None, key)

    def test_arzypher_encoder_13(self):
        r = pad('XYZ', 2)
        self.assertEqual('XY', r)

    def test_arzypher_encoder_14(self):
        r = pad('XYZ', 4)
        self.assertEqual('0XYZ', r)

    def test_arzypher_encoder_X(self):
        total = 0
        for i in range(100):
            st = time.time()
            pkey = [512] * 512
            inp = pkey
            check_sum = None
            random_key = None

            b64, key = arzypher_encoder(
                private_key=PRIVATE_KEY,
                random_key=random_key,
                check_sum=check_sum,
                params_keys=pkey,
                params_data=inp,
                padding=None
            )

            decode, key = arzypher_decoder(
                private_key=PRIVATE_KEY,
                random_key=random_key,
                check_sum=check_sum,
                params_keys=pkey,
                encoded=b64,
                padding=None
            )
            total += time.time() - st
        print(total)
        self.assertLess(total, 2)


if __name__ == '__main__':
    unittest.main()
