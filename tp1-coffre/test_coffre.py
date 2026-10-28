import pytest
from cryptography.exceptions import InvalidTag
import coffre

FAST = dict(t=1, m=8 * 1024, p=4)   # parametres legers pour les tests
MDP, NOM, DATA = "correct horse battery", "rapport.txt", b"donnees secretes" * 10


def chif(mdp=MDP, nom=NOM, data=DATA):
    return coffre.chiffrer(mdp, nom, data, **FAST)


def test_aller_retour():
    assert coffre.dechiffrer(MDP, NOM, chif()) == DATA


def test_chiffrement_probabiliste():
    a, b = chif(), chif()
    assert a != b and a[16:44] != b[16:44]   # sel et nonce differents


def test_mauvais_mot_de_passe():
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mauvais", NOM, chif())


@pytest.mark.parametrize("pos", [coffre.LEN_ENTETE + 3, -1])
def test_octet_modifie(pos):
    blob = bytearray(chif())
    blob[pos] ^= 0x01
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, bytes(blob))


def test_entete_modifie():
    blob = bytearray(chif())
    blob[20] ^= 0x01    # un octet du sel
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, bytes(blob))


def test_fichier_renomme():
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, "autre.txt", chif())


def test_format_inconnu():
    blob = b"XXXX" + chif()[4:]
    with pytest.raises(ValueError):
        coffre.dechiffrer(MDP, NOM, blob)


def test_rechiffrement():
    blob = coffre.rechiffrer(MDP, "nouveau", NOM, chif(), **FAST)
    assert coffre.dechiffrer("nouveau", NOM, blob) == DATA
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, blob)


def test_anciens_parametres_lisibles():
    ancien = coffre.chiffrer(MDP, NOM, DATA, t=1, m=8 * 1024, p=4)
    nouveau = coffre.chiffrer(MDP, NOM, DATA, t=2, m=16 * 1024, p=4)
    assert coffre.dechiffrer(MDP, NOM, ancien) == coffre.dechiffrer(MDP, NOM, nouveau)
