"""Real-PQC regression tests for modules/quantum/encryption.py and
web/routers/quantum.py.

Covers the mock-to-real rewrite: every operation now goes through liboqs (or
liboqs + the `cryptography` package for the classical half of a hybrid
scheme) with no simulated/fallback path left. These tests require liboqs to
actually be loadable in the environment running pytest (LD_LIBRARY_PATH /
OQS_INSTALL_PATH pointing at a built liboqs, or the library registered via
ldconfig as the Dockerfile does) -- see the PQCUnavailableError section at
the bottom for the "liboqs missing" behavior, which is tested by forcing
that path rather than by actually uninstalling liboqs.
"""

import asyncio
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.models import User
import web.routers.quantum as quantum_router
import modules.quantum.encryption as qe


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int = 1, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _isolated_keys_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(qe, "KEYS_DIR", tmp_path / "quantum_keys")


# --------------------------------------------------------------------------
# KEM round-trip
# --------------------------------------------------------------------------

class TestKemRoundTrip:
    @pytest.mark.parametrize("algorithm", ["kyber768", "kyber1024"])
    def test_encapsulate_decapsulate_match(self, algorithm):
        kp = qe.generate_keypair(algorithm)
        enc = qe.encapsulate(kp["public_key"], algorithm)
        dec = qe.decapsulate(kp["private_key"], enc["ciphertext"], algorithm)
        assert enc["shared_secret"] == dec["shared_secret"]
        assert enc["mode"] == "liboqs"
        assert dec["mode"] == "liboqs"

    def test_wrong_private_key_does_not_match(self):
        kp1 = qe.generate_keypair("kyber768")
        kp2 = qe.generate_keypair("kyber768")
        enc = qe.encapsulate(kp1["public_key"], "kyber768")
        dec = qe.decapsulate(kp2["private_key"], enc["ciphertext"], "kyber768")
        assert enc["shared_secret"] != dec["shared_secret"]

    def test_demo_kem_roundtrip_matches(self):
        result = qe.demo_kem_roundtrip("kyber768")
        assert result["match"] is True


# --------------------------------------------------------------------------
# Sign / verify
# --------------------------------------------------------------------------

class TestSignVerify:
    @pytest.mark.parametrize("algorithm", ["dilithium3", "sphincs_sha2", "falcon512"])
    def test_sign_then_verify_succeeds(self, algorithm):
        kp = qe.generate_keypair(algorithm)
        s = qe.sign(kp["private_key"], "hello quantum world", algorithm)
        v = qe.verify(kp["public_key"], "hello quantum world", s["signature"], algorithm)
        assert v["valid"] is True

    @pytest.mark.parametrize("algorithm", ["dilithium3", "sphincs_sha2", "falcon512"])
    def test_verify_rejects_tampered_message(self, algorithm):
        kp = qe.generate_keypair(algorithm)
        s = qe.sign(kp["private_key"], "original message", algorithm)
        v = qe.verify(kp["public_key"], "tampered message", s["signature"], algorithm)
        assert v["valid"] is False

    def test_verify_rejects_forged_signature(self):
        kp = qe.generate_keypair("dilithium3")
        other_kp = qe.generate_keypair("dilithium3")
        s = qe.sign(other_kp["private_key"], "hello", "dilithium3")
        v = qe.verify(kp["public_key"], "hello", s["signature"], "dilithium3")
        assert v["valid"] is False

    def test_demo_sign_roundtrip_success(self):
        result = qe.demo_sign_roundtrip("dilithium3")
        assert result["verified_correct_message"] is True
        assert result["verified_tampered_message"] is False
        assert result["success"] is True


# --------------------------------------------------------------------------
# Encrypt / decrypt (AES-256-GCM keyed by a real KEM-derived shared secret)
# --------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_round_trip_recovers_plaintext(self):
        kp = qe.generate_keypair("kyber768")
        enc_kem = qe.encapsulate(kp["public_key"], "kyber768")
        dec_kem = qe.decapsulate(kp["private_key"], enc_kem["ciphertext"], "kyber768")

        enc = qe.encrypt_data("the secret plan", dec_kem["shared_secret"])
        dec = qe.decrypt_data(enc["ciphertext"], enc["nonce"], enc_kem["shared_secret"])

        assert dec["success"] is True
        assert dec["plaintext"] == "the secret plan"

    def test_wrong_key_fails(self):
        kp = qe.generate_keypair("kyber768")
        enc_kem = qe.encapsulate(kp["public_key"], "kyber768")
        dec_kem = qe.decapsulate(kp["private_key"], enc_kem["ciphertext"], "kyber768")
        enc = qe.encrypt_data("the secret plan", dec_kem["shared_secret"])

        other_kp = qe.generate_keypair("kyber768")
        other_enc_kem = qe.encapsulate(other_kp["public_key"], "kyber768")
        dec = qe.decrypt_data(enc["ciphertext"], enc["nonce"], other_enc_kem["shared_secret"])

        assert dec["success"] is False

    def test_demo_encrypt_roundtrip(self):
        result = qe.demo_encrypt_roundtrip("kyber768", "OPTISEC secret payload")
        assert result["round_trip_success"] is True
        assert result["recovered_plaintext"] == "OPTISEC secret payload"
        assert result["wrong_key_rejected"] is True


# --------------------------------------------------------------------------
# Hybrid schemes: Kyber+X25519 KEM, Dilithium+Ed25519 signature
# --------------------------------------------------------------------------

class TestHybridSchemes:
    def test_hybrid_kem_roundtrip_matches(self):
        kp = qe.generate_hybrid_keypair("kyber768_x25519")
        enc = qe.hybrid_encapsulate(kp["pqc_public_key"], kp["classical_public_key"], "kyber768_x25519")
        dec = qe.hybrid_decapsulate(
            kp["pqc_private_key"], kp["classical_private_key"],
            enc["pqc_ciphertext"], enc["ephemeral_classical_public_key"], "kyber768_x25519",
        )
        assert enc["shared_secret"] == dec["shared_secret"]
        assert enc["hybrid"] is True

    def test_hybrid_kem_breaks_if_classical_half_wrong(self):
        kp = qe.generate_hybrid_keypair("kyber768_x25519")
        other_kp = qe.generate_hybrid_keypair("kyber768_x25519")
        enc = qe.hybrid_encapsulate(kp["pqc_public_key"], kp["classical_public_key"], "kyber768_x25519")
        # Decapsulate with the right PQC key but the WRONG classical private key.
        dec = qe.hybrid_decapsulate(
            kp["pqc_private_key"], other_kp["classical_private_key"],
            enc["pqc_ciphertext"], enc["ephemeral_classical_public_key"], "kyber768_x25519",
        )
        assert enc["shared_secret"] != dec["shared_secret"]

    def test_hybrid_sign_verify_roundtrip(self):
        kp = qe.generate_hybrid_keypair("dilithium3_ed25519")
        s = qe.hybrid_sign(kp["pqc_private_key"], kp["classical_private_key"], "hybrid message",
                            "dilithium3_ed25519")
        v = qe.hybrid_verify(kp["pqc_public_key"], kp["classical_public_key"], "hybrid message",
                              s["pqc_signature"], s["classical_signature"], "dilithium3_ed25519")
        assert v["valid"] is True
        assert v["pqc_valid"] is True
        assert v["classical_valid"] is True

    def test_hybrid_verify_fails_if_either_half_invalid(self):
        kp = qe.generate_hybrid_keypair("dilithium3_ed25519")
        s = qe.hybrid_sign(kp["pqc_private_key"], kp["classical_private_key"], "hybrid message",
                            "dilithium3_ed25519")
        v = qe.hybrid_verify(kp["pqc_public_key"], kp["classical_public_key"], "tampered message",
                              s["pqc_signature"], s["classical_signature"], "dilithium3_ed25519")
        assert v["valid"] is False

    def test_demo_hybrid_kem_roundtrip(self):
        result = qe.demo_hybrid_roundtrip("kyber768_x25519")
        assert result["match"] is True
        assert result["hybrid"] is True

    def test_demo_hybrid_sign_roundtrip(self):
        result = qe.demo_hybrid_roundtrip("dilithium3_ed25519")
        assert result["valid"] is True
        assert result["tampered_rejected"] is True

    def test_hybrid_keypair_never_persists_private_material(self):
        kp = qe.generate_hybrid_keypair("kyber768_x25519", user_id=1)
        stored = qe.list_keys(user_id=1, is_admin=False)
        assert len(stored) == 1
        assert "pqc_private_key" not in stored[0]
        assert "classical_private_key" not in stored[0]


# --------------------------------------------------------------------------
# Crypto Assessment: computed, not a fixed table -- different inputs must
# give genuinely different, non-hardcoded answers.
# --------------------------------------------------------------------------

class TestCryptoAssessment:
    def test_rsa_sizes_give_different_qubit_estimates(self):
        a = qe.assess_crypto_strength("rsa-2048")
        b = qe.assess_crypto_strength("rsa-4096")
        assert a["quantum_broken"] is True
        assert b["quantum_broken"] is True
        assert a["shor_estimated_logical_qubits"] != b["shor_estimated_logical_qubits"]
        assert b["shor_estimated_logical_qubits"] > a["shor_estimated_logical_qubits"]

    def test_unhardcoded_rsa_size_still_computed(self):
        # rsa-3072 was never in the old static lookup table.
        result = qe.assess_crypto_strength("rsa-3072")
        assert result["quantum_broken"] is True
        assert result["key_bits"] == 3072
        assert result["shor_estimated_logical_qubits"] == 2 * 3072 + 3

    def test_aes_128_vs_256_differ_under_grover(self):
        a = qe.assess_crypto_strength("aes-128")
        b = qe.assess_crypto_strength("aes-256")
        assert a["grover_effective_security_bits"] == 64
        assert b["grover_effective_security_bits"] == 128
        assert a["quantum_broken"] is False
        assert b["quantum_broken"] is False

    def test_ecdsa_uses_ecc_qubit_formula(self):
        result = qe.assess_crypto_strength("ecdsa-p256")
        assert result["quantum_broken"] is True
        assert result["shor_estimated_logical_qubits"] == 6 * 256

    def test_pqc_algorithm_is_quantum_safe(self):
        result = qe.assess_crypto_strength("kyber768")
        assert result["quantum_broken"] is False
        assert result["risk"] == "low"
        assert result["estimated_classical_security_bits"] == 192  # security_level 3

    def test_unparseable_algorithm_is_honestly_unknown(self):
        result = qe.assess_crypto_strength("totally-made-up-cipher-xyz")
        assert result["quantum_broken"] == "unknown"
        assert result["risk"] == "unknown"

    def test_not_all_inputs_give_the_same_result(self):
        # Regression guard against ever going back to a fixed/constant table.
        results = [
            qe.assess_crypto_strength(a)
            for a in ("rsa-2048", "aes-256", "ecdsa-p256", "sha-256", "kyber768")
        ]
        risks = {r["risk"] for r in results}
        assert len(risks) > 1


# --------------------------------------------------------------------------
# Router-level: new endpoints return plain dicts, not coroutines, and stay
# scoped like the existing keypair/encapsulate endpoints.
# --------------------------------------------------------------------------

class TestRouterEndpoints:
    def test_decapsulate_endpoint(self):
        kp = qe.generate_keypair("kyber768")
        enc = qe.encapsulate(kp["public_key"], "kyber768")
        result = _run(quantum_router.decapsulate(
            _FakeRequest({"private_key": kp["private_key"], "ciphertext": enc["ciphertext"],
                          "algorithm": "kyber768"}),
            user=_fake_user(),
        ))
        assert result["shared_secret"] == enc["shared_secret"]

    def test_sign_and_verify_endpoints(self):
        kp = qe.generate_keypair("dilithium3")
        sig_result = _run(quantum_router.sign_message(
            _FakeRequest({"private_key": kp["private_key"], "message": "router test",
                          "algorithm": "dilithium3"}),
            user=_fake_user(),
        ))
        verify_result = _run(quantum_router.verify_signature(
            _FakeRequest({"public_key": kp["public_key"], "message": "router test",
                          "signature": sig_result["signature"], "algorithm": "dilithium3"}),
            user=_fake_user(),
        ))
        assert verify_result["valid"] is True

    def test_decrypt_endpoint(self):
        kp = qe.generate_keypair("kyber768")
        enc_kem = qe.encapsulate(kp["public_key"], "kyber768")
        dec_kem = qe.decapsulate(kp["private_key"], enc_kem["ciphertext"], "kyber768")
        enc_data = qe.encrypt_data("router decrypt test", dec_kem["shared_secret"])

        result = _run(quantum_router.decrypt_data(
            _FakeRequest({"ciphertext": enc_data["ciphertext"], "nonce": enc_data["nonce"],
                          "shared_secret": enc_kem["shared_secret"]}),
            user=_fake_user(),
        ))
        assert result["success"] is True
        assert result["plaintext"] == "router decrypt test"

    def test_hybrid_keypair_endpoint_strips_private_keys(self):
        result = _run(quantum_router.generate_hybrid_keypair(
            _FakeRequest({"scheme": "kyber768_x25519"}), user=_fake_user(),
        ))
        assert "pqc_private_key" not in result
        assert "classical_private_key" not in result
        assert "pqc_public_key" in result

    def test_demo_endpoints_prove_roundtrips(self):
        kem_demo = _run(quantum_router.demo_kem(
            _FakeRequest({"algorithm": "kyber768"}), user=_fake_user(),
        ))
        assert kem_demo["match"] is True

        sign_demo = _run(quantum_router.demo_sign(
            _FakeRequest({"algorithm": "dilithium3"}), user=_fake_user(),
        ))
        assert sign_demo["success"] is True

        encrypt_demo = _run(quantum_router.demo_encrypt(
            _FakeRequest({"algorithm": "kyber768"}), user=_fake_user(),
        ))
        assert encrypt_demo["round_trip_success"] is True

        hybrid_demo = _run(quantum_router.demo_hybrid(
            _FakeRequest({"scheme": "kyber768_x25519"}), user=_fake_user(),
        ))
        assert hybrid_demo["match"] is True


# --------------------------------------------------------------------------
# PQCUnavailableError: liboqs missing must fail explicitly, never silently
# fabricate keys/secrets/"success". Forces the unavailable path rather than
# actually uninstalling liboqs.
# --------------------------------------------------------------------------

class TestPQCUnavailable:
    @pytest.fixture(autouse=True)
    def _force_unavailable(self, monkeypatch):
        monkeypatch.setattr(qe, "_oqs_module", None)
        monkeypatch.setattr(qe, "_oqs_unavailable_reason", None)
        monkeypatch.setattr(qe.ctypes.util, "find_library", lambda name: None)
        monkeypatch.delenv("OQS_INSTALL_PATH", raising=False)

    def test_generate_keypair_raises_explicitly(self):
        with pytest.raises(qe.PQCUnavailableError, match="Real PQC unavailable"):
            qe.generate_keypair("kyber768")

    def test_encapsulate_raises_explicitly(self):
        with pytest.raises(qe.PQCUnavailableError):
            qe.encapsulate(base64.b64encode(b"x" * 1184).decode(), "kyber768")

    def test_sign_raises_explicitly(self):
        with pytest.raises(qe.PQCUnavailableError):
            qe.sign(base64.b64encode(b"x" * 4000).decode(), "hello", "dilithium3")

    def test_router_translates_to_http_503(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _run(quantum_router.generate_keypair(
                _FakeRequest({"algorithm": "kyber768"}), user=_fake_user(),
            ))
        assert exc_info.value.status_code == 503
        assert "liboqs" in exc_info.value.detail.lower()

    def test_no_fallback_key_material_is_ever_returned(self):
        # The historical bug this whole rewrite fixes: liboqs missing used
        # to silently return random bytes dressed up as a "successful"
        # keypair/shared-secret. Confirm that path is gone for good.
        with pytest.raises(qe.PQCUnavailableError):
            qe.generate_keypair("kyber768")
        with pytest.raises(qe.PQCUnavailableError):
            qe.decapsulate(base64.b64encode(b"x" * 2400).decode(),
                            base64.b64encode(b"x" * 1088).decode(), "kyber768")
