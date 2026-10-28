# Ingénierie de la cryptographie – Travaux pratiques

**École Polytechnique de Ouagadougou – IGIT 2 Génie Informatique**
Étudiant : TRAORE Inoussa · Enseignant : Dr. Zakaria SAWADOGO · Année 2026–2027

Le rapport complet est dans [`docs/Rapport_final.pdf`](docs/Rapport_final.pdf).

| Dossier | Contenu |
|---|---|
| `tp1-coffre/` | Mini-coffre de fichiers : Argon2id + HKDF + AES-256-GCM, tests pytest |
| `tp2-pki/` | PKI à deux niveaux avec OpenSSL (`pki.sh`, `racine.cnf`, `inter.cnf`) |
| `tp3-tls/` | nginx en mTLS, supervision (`surveiller.py`), renouvellement (`renouveler.sh`) |

## Prérequis
openEuler (OS gratuit et open source basé sur Linux) ou autre machine lunix, Python ≥ 3.10, OpenSSL ≥ 3.0, nginx (TP 3 uniquement).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## TP 1 – Chiffrement authentifié
```bash
cd tp1-coffre
python -m pytest -v     # 10 tests attendus
python demo.py          # démonstration (dérivation Argon2id ~0,5 s)
```

## TP 2 – PKI
```bash
cd tp2-pki
./pki.sh                # crée racine/, inter/, serveur, alice, bob, crls.pem
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.tp.local serveur.crt
# Révocation d'Alice
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf  -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
openssl verify -crl_check_all -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -CRLfile crls.pem alice.crt      # attendu : certificate revoked
```
`pki.sh` refuse d'écraser une PKI existante ; supprimer `racine/` et `inter/` pour recommencer.

## TP 3 – Canal TLS (nécessite sudo, nginx)
```bash
cd tp2-pki   # après ./pki.sh
cat serveur.crt inter/inter.crt > serveur_chaine.crt
cat bob.crt inter/inter.crt > bob_chaine.crt
sudo mkdir -p /etc/nginx/tls
sudo install -m 600 serveur.key /etc/nginx/tls/serveur.key
sudo install -m 644 serveur_chaine.crt racine/racine.crt crls.pem /etc/nginx/tls/
echo "127.0.0.1 www.tp.local" | sudo tee -a /etc/hosts
sudo cp ../tp3-tls/nginx-tp.conf /etc/nginx/conf.d/tp.conf
sudo nginx -t && sudo systemctl reload nginx

curl --cacert racine/racine.crt --cert bob_chaine.crt --key bob.key https://www.tp.local/
python3 ../tp3-tls/surveiller.py /etc/nginx/tls ; echo "exit=$?"
```
Renouvellement (le dossier PKI doit contenir `inter.cnf`, `racine/`, `inter/`) :
```bash
sudo PKI=$PWD ../tp3-tls/renouveler.sh              # ne fait rien si > 30 jours
sudo PKI=$PWD SEUIL=100 ../tp3-tls/renouveler.sh    # force le test
```
Planification : `tp3-tls/renouveler-tls.service` et `.timer` (systemd).

## Sécurité
Les clés privées et certificats générés sont exclus par `.gitignore` : **ils ne doivent jamais être publiés**. Toutes les manipulations sont limitées aux noms `*.tp.local` et à la machine locale.
