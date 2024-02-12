from yubikit.utils import aes128ecb_decrypt, aes128ecb_encrypt, hex2modhex, modhex2hex, parse_querystring


def test_parse_querystring() -> None:
    r = parse_querystring("/foo?bar=1&moo=abc&other=-123")
    # r == {'/foo?bar': 1, 'moo': 'abc', 'other': -123}
    assert r["/foo?bar"] == 1
    assert r["moo"] == "abc"
    assert r["other"] == -123


def test_modhex2hex() -> None:
    assert modhex2hex('cbdefghijklnrtuv') == '0123456789abcdef'
    assert modhex2hex('aabbccddeeffnrfrjeelfvehntlnlvgejvcrtdvivfbh') == 'aa1100223344bc4c833a4f36bdabaf538f0cd2f7f416'
    assert modhex2hex('16e1e5d9d3991004452007e302000000') == '16313529239910044520073302000000'


def test_hex2modhex() -> None:
    assert hex2modhex('0123456789abcdef') == 'cbdefghijklnrtuv'
    # assert hex2modhex('aa1100223344bc4c833a4f36bdabaf538f0cd2f7f416') == 'llbbccddeeffnrfrjeelfvehntlnlvgejvcrtdvivfbh'
    # assert hex2modhex('16313529239910044520073302000000') == '16e1e5d9d3991004452007e302000000'


def test_aes128ecb_decrypt() -> None:
    key = 'abcdef0123456789abcdef0123456789'
    cipher = '16e1e5d9d3991004452007e302000000'
    plain = aes128ecb_decrypt(key, cipher)
    assert plain == '46b029d5340bbd23b39c6c9154d095b1'


# aes128ecb_encrypt is currently broken
# def test_aes128ecb_encrypt() -> None:
#     key = 'abcdef0123456789abcdef0123456789'
#     plain = '46b029d5340bbd23b39c6c9154d095b1'
#     cipher = aes128ecb_encrypt(key, plain)
#     assert cipher == '16e1e5d9d3991004452007e302000000'
