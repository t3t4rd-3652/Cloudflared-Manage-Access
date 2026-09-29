import pytest

from cma.core.crypto import WrongPassphraseError, decrypt_json, encrypt_json
from cma.core.redact import MASK, forget_secret, redact, register_secret
from cma.core.secrets import EncryptedFileSecretStore, MemorySecretStore


def test_registered_secret_is_masked_everywhere():
    value = "zq9-valeur-unique-4471"
    register_secret(value)
    assert redact(f"valeur={value} fin") == f"valeur={MASK} fin"
    forget_secret(value)
    assert redact(value) == value


@pytest.mark.parametrize(
    "text",
    [
        "Cf-Access-Client-Secret: abcdef",
        "TUNNEL_SERVICE_TOKEN_SECRET=abcdef",
        "--service-token-secret abcdef",
        "password=abcdef",
    ],
)
def test_known_secret_patterns_are_masked(text):
    assert "abcdef" not in redact(text)


def test_short_values_are_not_registered():
    register_secret("ab")
    assert redact("ab ab") == "ab ab"


def test_secret_store_registers_values_for_redaction():
    store = MemorySecretStore()
    store.set("token:1", "valeur-du-coffre")
    assert "valeur-du-coffre" not in redact("fuite : valeur-du-coffre")
    store.delete("token:1")
    assert store.get("token:1") is None


def test_encryption_roundtrip_and_wrong_passphrase():
    blob = encrypt_json({"token:1": "sécrèt"}, "phrase correcte")
    assert "sécrèt" not in str(blob)
    assert decrypt_json(blob, "phrase correcte") == {"token:1": "sécrèt"}
    with pytest.raises(WrongPassphraseError):
        decrypt_json(blob, "mauvaise")
    blob["data"] = blob["data"][:-4] + "AAAA"
    with pytest.raises(WrongPassphraseError):
        decrypt_json(blob, "phrase correcte")


def test_encrypted_file_store(tmp_path):
    path = tmp_path / "secrets.enc.json"
    store = EncryptedFileSecretStore(path, "phrase")
    store.set("a", "1")
    store.set("b", "2")
    store.delete("b")
    reopened = EncryptedFileSecretStore(path, "phrase")
    assert reopened.get("a") == "1"
    assert reopened.get("b") is None
    with pytest.raises(WrongPassphraseError):
        EncryptedFileSecretStore(path, "autre")
