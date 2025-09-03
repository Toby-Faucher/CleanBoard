from bcrypt import gensalt, hashpw


def hash_password(password: str) -> str:
    salt = gensalt()
    hashed_pw = hashpw(password=password.encode('utf-8'), salt=salt)
    return hashed_pw.decode('utf-8')
