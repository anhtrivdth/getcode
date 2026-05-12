from app.services.parser import extract_code


def test_extract_numeric_otp():
    body = "Welcome.\nOTP: 123456\nDo not share."
    code = extract_code(body=body, patterns=[r"OTP[:\s]+(\d{6})"])
    assert code == "123456"


def test_extract_alpha_numeric():
    body = "Your verification code is AB12CD"
    code = extract_code(body=body, patterns=[r"code is ([A-Z0-9]{6})"])
    assert code == "AB12CD"


def test_sender_subject_filter_reduce_false_positive():
    body = "OTP: 654321"
    code = extract_code(
        body=body,
        patterns=[r"OTP[:\s]+(\d{6})"],
        sender="newsletter@example.com",
        subject="Weekly digest",
        sender_filter="no-reply@example.com",
        subject_filter="Your OTP",
    )
    assert code is None
