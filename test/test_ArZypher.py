import secrets
import unittest
import time
from ArZypher import arzypher_decoder, arzypher_encoder
from ArZypher.ArZypher import (
    pad
)
import string
import math

PRIVATE_KEY = 'rule the world'


class MyTestCase(unittest.TestCase):
    def test_arzypher_encoder_void(self):
        pkey = []
        inp = []
        check_sum = None
        random_key = None

        b64, key = arzypher_encoder(
            private_key=None,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        self.assertEqual('', b64)
        self.assertEqual(0, key)

    def test_arzypher_encoder_001(self):
        pkey = [8]
        inp = [8]
        check_sum = None
        random_key = None

        b64, key_e = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        # print(b64)

        decode, key_d = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('Gg', b64)
        self.assertEqual(key_e, key_d)

    def test_arzypher_encoder_002(self):
        pkey = [2]
        inp = [3]
        check_sum = None
        random_key = None

        b64, key_e = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key_d = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('7Q', b64)
        self.assertEqual(key_e, key_d)

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

        b64, key_e = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key_d = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('1g', b64)
        self.assertEqual(key_e, key_d)

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

        b64, key_e = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key_d = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual('5zU', b64)
        self.assertEqual(key_e, key_d)

    def test_arzypher_encoder_007(self):
        pkey = [2, 2, 2]
        inp = [3, 3, 2]
        check_sum = 256
        random_key = None

        b64, key_e = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key_d = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )
        self.assertEqual('-F0SoQzKnJcfl8yv30aksNV-wA9rCWt_ZOwK-_JOd-nX', b64)
        self.assertEqual(key_e, key_d)

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

        b64, key_e = arzypher_encoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        decode, key_d = arzypher_decoder(
            private_key=PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )
        self.assertEqual('1w', b64)
        self.assertEqual(key_e, key_d)

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

    def test_arzypher_encoder_021(self):
        for i in range(10000):
            # if i % 100 == 0:
            #     print(i)
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

    def test_arzypher_encoder_022(self):
        pkey = [8, 24, 1]
        inp = [1, 1, 1]
        check_sum = None
        random_key = None

        # _PRIVATE_KEY = secrets.token_hex(32)
        _PRIVATE_KEY = 'rule the world'

        b64, key_e = arzypher_encoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        print(b64)
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

    def test_arzypher_encoder_023(self):
        pkey = [8, 8, 8, 8]
        inp = [64, 64, 64, 64]
        check_sum = None
        random_key = None

        b64, key_e = arzypher_encoder(
            private_key=None,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        print(b64)
        # print(len(b64))
        # print(b64[:64])

        decode, key_d = arzypher_decoder(
            private_key=None,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            encoded=b64,
            padding=None
        )

        self.assertEqual(inp, decode)
        self.assertEqual(key_e, key_d)

    def test_arzypher_encoder_024(self):
        pkey = [127, 240, 18]
        inp = [1, 1, 1]
        check_sum = 256
        random_key = None
        _PRIVATE_KEY = 'rule the world '
        # _PRIVATE_KEY = None

        b64, key_e = arzypher_encoder(
            private_key=_PRIVATE_KEY,
            random_key=random_key,
            check_sum=check_sum,
            params_keys=pkey,
            params_data=inp,
            padding=None
        )

        b64 = 'a'+b64[:-1]

        print(b64)

        # r1 = VMiTvhX4We9HajTIMXi2Lbd7MlshKCjEhVQz8VLkDOjnD1WfhlhMoW4OI4wlWHRUYZrvy7H5VG400z-NZBVbpQOEYy83nS8pAK06yCSGZPqc
        # r2 = mWRMCl1VVBlIV90VEApRbht11ZWQlcqC1jKBnDt918GDiAD7wj3J_YKzflsk1A0z-zWrrfxIYAldXkfzIn7Z-uvmagTq_ce5SHokMbvRPZFa

        # r3 =


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

    def test_arzypher_encoder_ENTROPY(self):
        def shannon_entropy(data):
            """
            Adapted from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
            by way of truffleHog (https://github.com/dxa4481/truffleHog)
            """
            if not data:
                return 0
            entropy = 0
            for x in string.printable:
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            return entropy

        max_e = 0
        mean_e = 0
        min_e = 100

        for i in range(1000):
            pkey = []
            inp = []
            for j in range(secrets.randbits(8) + 8):
                _s = 32 + secrets.randbits(8)
                pkey.append(_s)
                inp.append(secrets.randbits(_s))
            check_sum = 256
            random_key = 32

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

            entropy = shannon_entropy(b64)
            # print(entropy)
            if entropy > max_e:
                max_e = entropy
            if entropy < min_e:
                # print(entropy, b64)
                min_e = entropy

            mean_e += entropy

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

        print('min', min_e)
        print('mean', mean_e / 1000)
        print('max', max_e)

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
