from src.aip_hjs.crypto import generate_uuid7

def test_uuid7_format():
    uid = generate_uuid7()
    assert len(uid) == 36
    assert uid[14] == '7'  # 验证版本位是否为 7
