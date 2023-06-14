import secrets
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

        # print(b64)

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('CA', b64)
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
        self.assertEqual('wA', b64)
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
        self.assertEqual('_Q', b64)
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
        self.assertEqual('w-4', b64)
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
        self.assertEqual('jW5JEAlQd2UB-kzfPnRUtMyPvpZGecLq390kTyvUpST4', b64)
        self.assertEqual(None, key)

    def test_arzypher_encoder_008(self):
        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=None,
            check_sum=513,
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
        self.assertEqual('_A', b64)
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

    def test_arzypher_encoder_015(self):
        pkey = [32]
        inp = [1]
        check_sum = 256
        random_key = 256 - 16

        _PRIVATE_KEY = secrets.token_hex(32)

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        # print(b64)
        # print(b64[:64])

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

    def test_arzypher_encoder_016(self):
        pkey = [256]
        inp = [secrets.randbits(256)]
        check_sum = 256
        random_key = 256

        _PRIVATE_KEY = 'RULE_THE_WORLD'

        b64, key = arzypher_encoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key = arzypher_decoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertNotEqual(None, key)

    def test_arzypher_encoder_017(self):
        pkey = [256]
        inp = [secrets.randbits(256)]
        check_sum = 256
        random_key = 256

        _PRIVATE_KEY = 'RULE_THE_WORLD'

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        b64 = 'a' + b64

        decode, key = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual([0], decode)
        self.assertEqual(None, key)

    def test_arzypher_encoder_018(self):
        pkey = [32, 24, 8, 32, 49]
        inp = [4, 3, 2, 1, 1]
        check_sum = 256
        random_key = 32

        b64, key = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=True
        )

        # print(b64)
        # print(b64[:64])

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

    def test_arzypher_encoder_019(self):
        pkey = [[str, 11 * 8], 1, [int, 1]]
        inp = ['["hello w"]', 1, 0]
        check_sum = 256
        random_key = 32

        _PRIVATE_KEY = secrets.token_hex(32)

        b64, key = arzypher_encoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        # print(b64)
        # print(len(b64))
        # print(b64[:64])

        decode, key = arzypher_decoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)

        # self.assertNotEqual(None, key)

    def test_arzypher_encoder_020(self):
        pkey = [8, 24, 1]

        inp = [1, 848158, 1]
        check_sum = None
        random_key = None

        # _PRIVATE_KEY = secrets.token_hex(32)
        _PRIVATE_KEY = ''

        b64, key = arzypher_encoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        # print(b64)
        # print(len(b64))
        # print(b64[:64])

        decode, key = arzypher_decoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual(None, key)

    def test_arzypher_encoder_021(self):
        for i in range(100):
            # print(i)
            pkey = []
            inp = []
            for j in range(secrets.randbits(8)):
                _s = secrets.randbits(8) + 1
                pkey.append(_s)
                inp.append(secrets.randbits(_s))
            check_sum = secrets.choice([None, secrets.randbits(9)])
            random_key = secrets.choice([None, secrets.randbits(8)])

            _PRIVATE_KEY = secrets.token_hex(32)
            # _PRIVATE_KEY = ''

            b64, key_e = arzypher_encoder(
                private_key=_PRIVATE_KEY,
                random_key=random_key,
                check_sum=check_sum,
                params_keys=pkey,
                params_data=inp,
                padding=None
            )

            # print(b64)
            # print(len(b64))
            # print(b64[:64])

            decode, key_d = arzypher_decoder(
                private_key=_PRIVATE_KEY,
                random_key=random_key,
                check_sum=check_sum,
                params_keys=pkey,
                encoded=b64,
                padding=None
            )

            self.assertEqual(inp, decode)
            self.assertEqual(key_e, key_d)

    def test_arzypher_encoder_Z(self):
        for i in range(100):
            pkey = []
            inp = []
            for j in range(secrets.randbits(8)):
                _s = secrets.randbits(8) + 1
                pkey.append(_s)
                inp.append(secrets.randbits(_s))
            check_sum = secrets.choice([None, secrets.randbits(8)])
            random_key = secrets.choice([None, secrets.randbits(8)])

            _PRIVATE_KEY = secrets.token_hex(32)

            b64, key_e = arzypher_encoder(
                private_key=_PRIVATE_KEY,
                random_key=random_key,
                check_sum=check_sum,
                params_keys=pkey,
                params_data=inp,
                padding=None
            )

            # print(b64)
            # print(len(b64))
            # print(b64[:64])

            decode, key_d = arzypher_decoder(
                private_key=_PRIVATE_KEY,
                random_key=random_key,
                check_sum=check_sum,
                params_keys=pkey,
                encoded=b64,
                padding=None
            )

            self.assertEqual(inp, decode)
            self.assertEqual(key_e, key_d)

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

    def test_arzypher_encoder_Y(self):
        private_key = ''
        params_keys = [
            8,
            24,
            1
        ]
        params_data = [
            1,
            848158,
            1
        ]
        check_sum = 15  # HS256
        random_key = None  # 32 bits for the random token generator

        b64, key = arzypher_encoder(
            private_key=private_key,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=params_keys,
            params_data=params_data,
            padding=None
        )

        print(b64)

        decode, key = arzypher_decoder(
            private_key=private_key,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=params_keys,
            encoded=b64,
            padding=None
        )
        print(decode)


if __name__ == '__main__':
    unittest.main()
