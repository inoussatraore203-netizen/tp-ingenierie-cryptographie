#!/usr/bin/env bash
# pki.sh - construit la PKI du TP 2 (racine, intermediaire, serveur, clients)
# Usage : ./pki.sh   (refuse d'ecraser une PKI existante)
set -euo pipefail

SUJET_AC="/C=BF/O=Universite TP"
[ -e racine/racine.key ] && { echo "PKI deja presente : supprimez racine/ et inter/" >&2; exit 1; }

# --- Arborescence des deux autorites ---------------------------------------
for ac in racine inter; do
  mkdir -p "$ac"/{newcerts,crl}
  : > "$ac/index.txt"
  echo 1000 > "$ac/serial"
  echo 1000 > "$ac/crlnumber"
done
umask 077   # les cles privees ne sont lisibles que par leur proprietaire

# --- Etape 2 : AC racine (P-384, 10 ans) -----------------------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "$SUJET_AC/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

# --- Etape 3 : AC intermediaire (P-256, 5 ans) -----------------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key -sha256 \
  -subj "$SUJET_AC/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# --- Etape 4 : certificats de feuille (P-256, 90 jours) --------------------
# emettre <nom_fichier> <CN> <SAN> <section d'extensions>
emettre() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" \
    -addext "subjectAltName=$3" -out "$1.csr"
  openssl ca -batch -notext -config inter.cnf -extensions "$4" -days 90 \
    -in "$1.csr" -out "$1.crt"
}
emettre serveur "www.tp.local"   "DNS:www.tp.local,DNS:tp.local" ext_serveur
emettre alice   "alice@tp.local" "email:alice@tp.local"          ext_client
emettre bob     "bob@tp.local"   "email:bob@tp.local"            ext_client

# --- CRL initiales (vides) et fichier combine ------------------------------
openssl ca -config inter.cnf  -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
echo "PKI creee : racine/racine.crt inter/inter.crt serveur.crt alice.crt bob.crt"
