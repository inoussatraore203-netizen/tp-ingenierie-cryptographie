"""coffre.py - mini-coffre de fichiers (format CFR1)."""
import os
import struct

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"CFR1"
T, M, P = 3, 128 * 1024, 4          # temps, memoire (Kio), parallelisme
LEN_SEL, LEN_NONCE, LEN_TAG = 16, 12, 16
LEN_ENTETE = 4 + 12 + LEN_SEL + LEN_NONCE   # 44 octets
M_MAX, T_MAX, P_MAX = 1024 * 1024, 20, 16   # bornes anti-DoS (1 Gio)


def cle_maitresse(mot_de_passe: str, sel: bytes, t=T, m=M, p=P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(secret=mot_de_passe.encode("utf-8"), salt=sel,
                           time_cost=t, memory_cost=m, parallelism=p,
                           hash_len=32, type=Type.ID)


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)


def _cle_fichier(mdp, sel, t, m, p) -> bytes:
    return sous_cle(cle_maitresse(mdp, sel, t, m, p), b"chiffrement-fichier")


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes,
             t=T, m=M, p=P) -> bytes:
    sel, nonce = os.urandom(LEN_SEL), os.urandom(LEN_NONCE)
    entete = MAGIC + struct.pack(">III", t, m, p) + sel + nonce
    cle = _cle_fichier(mot_de_passe, sel, t, m, p)
    ad = entete + nom.encode("utf-8")
    return entete + AESGCM(cle).encrypt(nonce, donnees, ad)


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if len(blob) < LEN_ENTETE + LEN_TAG or blob[:4] != MAGIC:
        raise ValueError("format inconnu")
    t, m, p = struct.unpack(">III", blob[4:16])
    if not (1 <= t <= T_MAX and 8 * p <= m <= M_MAX and 1 <= p <= P_MAX):
        raise ValueError("parametres hors bornes")
    sel = blob[16:16 + LEN_SEL]
    nonce = blob[32:32 + LEN_NONCE]
    entete = blob[:LEN_ENTETE]
    cle = _cle_fichier(mot_de_passe, sel, t, m, p)
    ad = entete + nom.encode("utf-8")
    return AESGCM(cle).decrypt(nonce, blob[LEN_ENTETE:], ad)  # InvalidTag


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str,
               blob: bytes, t=T, m=M, p=P) -> bytes:
    """Change le mot de passe et applique les parametres courants."""
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees, t, m, p)
