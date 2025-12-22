
def test_hash_and_verify_password(db_module):
    pw = "Test@1234"
    h = db_module.hash_password(pw)
    assert isinstance(h, str)
    assert h != pw
    assert db_module.verify_password(pw, h) is True
    assert db_module.verify_password("Wrong@1234", h) is False
