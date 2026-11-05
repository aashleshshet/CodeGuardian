# Intentionally unsafe baseline-only patterns. Never execute.
import pickle
import hashlib


def restore_session(payload):
    return pickle.loads(payload)


def legacy_digest(password):
    return hashlib.md5(password.encode()).hexdigest()
