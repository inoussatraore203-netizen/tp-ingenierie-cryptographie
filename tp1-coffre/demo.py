"""demo.py - demonstration du coffre (TP 1)."""
import coffre

MDP, NOM = "motdepasse-demo", "note.txt"
data = b"Contenu confidentiel du fichier.\n" * 30

b = coffre.chiffrer(MDP, NOM, data)
print(f"clair : {len(data)} octets ; chiffre : {len(b)} octets "
      f"(= {len(data)} + 44 + 16)")
print("en-tete (hex) :", b[:4].hex(), "|", b[4:16].hex(), "|",
      b[16:32].hex(), "|", b[32:44].hex())
t, m, p = (int.from_bytes(b[i:i + 4], "big") for i in (4, 8, 12))
print(f"identifiant = {b[:4]!r} ; t, m, p = {t}, {m} Kio ({m // 1024} Mio), {p}")
b2 = coffre.chiffrer(MDP, NOM, data)
print("deux chiffrements identiques ?", b == b2, "; sels egaux ?", b[16:32] == b2[16:32])
print("dechiffrement correct ?", coffre.dechiffrer(MDP, NOM, b) == data)
n = coffre.rechiffrer(MDP, "nouveau-mdp", NOM, b, t=4, m=128 * 1024, p=4)
print("apres rechiffrement : t =", int.from_bytes(n[4:8], "big"))
try:
    coffre.dechiffrer(MDP, NOM, n)
except Exception as e:
    print("ancien mot de passe ->", type(e).__name__)
print("nouveau mot de passe correct ?", coffre.dechiffrer("nouveau-mdp", NOM, n) == data)
