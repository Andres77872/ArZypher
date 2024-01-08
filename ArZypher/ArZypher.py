import random
import hashlib
import secrets
import base64
import hmac


def pad(value: str, max_length: int) -> str:
    """
    Complete the binary string with zeros to the right if max_length is bigger, then return a substring.

    :param value: Binary string
    :param max_length: Max length
    :return: String with the length of max_length
    """
    return value[:max_length].zfill(max_length)


def generate_hashcode(secret_key: str, key_string: str, max_length: int):
    """
    Generate a truncated hash code based on the given secret key and key string.

    :param secret_key: Secret key used for hashing.
    :param key_string: Key string to be hashed.
    :param max_length: Maximum length of the generated hash.
    :return: Hash code as a binary string.
    """
    # Select hashing algorithm based on max_length.
    if max_length <= 256:
        _h = hashlib.sha256
    elif max_length <= 384:
        _h = hashlib.sha384
    else:
        _h = hashlib.sha512

    # Fallback for an empty secret_key.
    secret_key = secret_key if secret_key else ''

    # Generate HMAC digest and return as a formatted binary string.
    dg_hmac = hmac.new(secret_key.encode('utf-8'), key_string.encode("utf-8"), _h).digest()
    return format(int.from_bytes(dg_hmac, 'big'), 'b')[:max_length].zfill(max_length)


def xor(params_keys: list[int], params: list[int] | str) -> str:
    """
    Perform XOR operation on the given parameters with random bits.

    :param params_keys: List of integers specifying the bit length for each parameter.
    :param params: List of integers or a binary string to be XORed.
    :return: Resulting binary string after the XOR operation.
    """
    # XOR operation for list inputs.
    if isinstance(params, list):
        return ''.join([f"{p ^ random.getrandbits(k):0{k}b}" for p, k in zip(params, params_keys)])
    else:
        # XOR operation for string input.
        _r = []
        _c = 0
        for k in params_keys:
            _r.append(f"{int(params[_c:_c + k], 2) ^ random.getrandbits(k):0{k}b}")
            _c += k
        return ''.join(_r)


def arzypher_encoder(private_key: str | None,
                     random_key: int | None,
                     check_sum: int | None,
                     padding: int | bool | None,
                     params_keys: list[int] | list[list[type[str | int], int]],
                     params_data: list[int] | list[str]) -> tuple[str, int | None]:
    """
    Generate Base64 code from int type data.

    **private_key** must be a strong string password, used only if the **check_sum** is not None.
    **random_key**, if None or zero, generates a consistent token, useful for non-sensitive data.
    **check_sum**, if None or zero, doesn't validate token integrity, allowing any compatible format.
    The **padding** parameter is not implemented yet.

    :param private_key: Server-side private key.
    :param random_key: (Optional) Byte length for the random key; different Base64 code each time.
    :param check_sum: (Optional) Base64 integrity check before decoding; max value 512 (SHA512).
    :param padding: Not implemented yet.
    :param params_keys: List with the byte length for each data.
    :param params_data: List with the ints to be encoded.
    :return: Base64 string coded to be used as URL, and the raw seed integer.
    """
    # Validate check_sum range.
    if check_sum is not None and (check_sum > 512 or check_sum < 0):
        return '', None

    # Ensure check_sum and random_key are integers.
    check_sum = check_sum if isinstance(check_sum, int) else 0
    random_key = random_key if isinstance(random_key, int) else 0

    # Prepare parameters data and keys.
    _params_data = []
    _params_keys = []
    for pk, pd in zip(params_keys, params_data):
        if isinstance(pd, int) and isinstance(pk, int):
            _params_data.append(pd)
            _params_keys.append(pk)
        elif isinstance(pk, list):
            _params_keys.append(pk[1])
            if pk[0] in {str, int}:
                if pk[0] == str:
                    _b = bytes(pd[:pk[1] // 8], 'utf-8')
                    _params_data.append(int.from_bytes(_b, 'big'))
                elif pk[0] == int:
                    _params_data.append(pd)
            else:
                return '', None
        else:
            return '', None
    params_data = _params_data
    params_keys = _params_keys

    # Clean up temporary variables.
    del _params_data, _params_keys

    # Validate parameter keys and data.
    for x, y in zip(params_keys, params_data):
        if x <= 0 or 2 ** x - 1 < y:
            return '', None

    # Calculate the fixed length for encoding.
    sm = check_sum + random_key + sum(params_keys)
    fix_length = sm % 8
    if fix_length:
        params_keys.append(8 - fix_length)
        params_data.append(0)

    # Prepare binary random key string and raw seed integer.
    binary_randomkey_string = ''
    raw_seed_int = 0
    if random_key is not None and random_key != 0:
        raw_seed_int += secrets.randbits(random_key)
        binary_randomkey_string = f"{raw_seed_int:0{random_key}b}"
    if private_key is not None:
        raw_seed_int += int.from_bytes(hashlib.sha256(private_key.encode('utf-8')).digest(), 'big')

    # Initialize random generator with raw seed integer if it's non-zero.
    if raw_seed_int != 0:
        random.seed(raw_seed_int)
        binary_params_string = xor(params_keys, params_data)
    else:
        # Generate a binary string with all params.
        binary_params_string = ''.join([f"{p:0{k}b}" for p, k in zip(params_data, params_keys)])

    # Prepare hash digest if check_sum is non-zero.
    dg = ''
    if check_sum != 0:
        _k = (binary_randomkey_string + binary_params_string + ''.join(map(str, params_keys)))
        dg = generate_hashcode(private_key, _k, check_sum)

    # Compile the final binary string.
    res = binary_randomkey_string + dg + binary_params_string

    # Convert to bytes and encode in Base64.
    key = bytes([int(res[i:i + 8], 2) for i in range(0, len(res), 8)])
    b64 = base64.b64encode(key, altchars=b'_-')
    b64 = b64.decode('utf-8').replace('=', '')

    return b64, raw_seed_int


def arzypher_decoder(private_key: str | None,
                     random_key: int | None,
                     check_sum: int | None,
                     padding: int | bool | None,
                     params_keys: list[int] | list[list[type[str | int], int]],
                     encoded: str) -> tuple[list[int] | list[str], int | None]:
    """
    Decode a Base64 encoded string, ensuring all parameters match those used during encoding.

    :param private_key: Server-side private key.
    :param random_key: (Optional) Byte length for the random key; affects code uniqueness.
    :param check_sum: (Optional) Base64 integrity check before decoding.
    :param padding: Not implemented yet.
    :param params_keys: List with the byte length for each data.
    :param encoded: Base64 encoded string.
    :return: List of decoded data (integers or strings), and the raw seed integer.
    """
    # Validate check_sum and encoded string.
    if check_sum is not None and (check_sum > 512 or check_sum < 0):
        return [0], None
    if len(encoded) % 4 == 1:
        return [0], None

    # Fix padding for Base64 decoding.
    padding_fix = (4 - len(encoded) % 4) % 4
    encoded = encoded + "=" * padding_fix if padding_fix else encoded

    # Ensure random_key and check_sum are integers.
    random_key = random_key if isinstance(random_key, int) else 0
    check_sum = check_sum if isinstance(check_sum, int) else 0

    # Prepare parameter keys and types.
    _params_keys = []
    _pd = []
    for pk in params_keys:
        if isinstance(pk, int):
            _params_keys.append(pk)
            _pd.append(int)
        elif isinstance(pk, list) and pk[0] in {str, int}:
            _params_keys.append(pk[1])
            _pd.append(pk[0])
        else:
            return [0], None
    params_keys = _params_keys

    # Calculate total bit length and fix_length if needed.
    sm = random_key + check_sum + sum(params_keys)
    _fx = False
    fix_length = sm % 8
    if fix_length:
        params_keys.append(8 - fix_length)
        _fx = True
        sm += 8 - fix_length

    # Decode Base64 and convert to binary string.
    d = base64.b64decode(encoded, altchars=b'_-')
    res = ''.join(['{:08b}'.format(i) for i in d])[-sm:]

    # Prepare raw seed from random key.
    raw_seed = 0
    if random_key != 0:
        s = res[:random_key]
        raw_seed += int(s, 2)
        t = res[random_key:]
    else:
        s = ''
        t = res

    if private_key is not None:
        raw_seed += int.from_bytes(hashlib.sha256(private_key.encode('utf-8')).digest(), 'big')

    # Initialize random generator with raw seed if non-zero.
    if raw_seed != 0:
        random.seed(raw_seed)

    # Verify and remove checksum from data.
    if check_sum != 0:
        hs = t[:check_sum]
        k = s + t[check_sum:sm] + ''.join([str(x) for x in params_keys])
        dg = generate_hashcode(private_key, k, check_sum)
        if dg != hs:
            return [0], None
        t = t[check_sum:]

    # Decrypt the remaining data.
    rk = xor(params_keys, t) if raw_seed != 0 else t

    # Extract and convert plaintext data from the decrypted binary string.
    res = []
    for i, _p in zip(params_keys, _pd):
        _di = int(rk[:i], 2)
        res.append(_di if _p == int else _di.to_bytes(len(rk[:i]) // 8, 'big').decode('utf-8'))
        rk = rk[i:]

    return res, raw_seed
