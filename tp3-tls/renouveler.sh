#!/usr/bin/env bash
# renouveler.sh - renouvellement du certificat du serveur (TP 3, etape 6)
# Variables : PKI (dossier de la PKI), TLS (dossier nginx), SEUIL (jours),
#             CN, SAN, FORCE=1 (renouveler meme si le seuil n'est pas atteint)
set -euo pipefail
umask 077

PKI=${PKI:-/opt/pki}
TLS=${TLS:-/etc/nginx/tls}
SEUIL=${SEUIL:-30}
CN=${CN:-www.tp.local}
SAN=${SAN:-DNS:www.tp.local,DNS:tp.local}
RELOAD_CMD=${RELOAD_CMD:-systemctl reload nginx}
DATE=$(date +%Y%m%dT%H%M%S)
ARCHIVE="$TLS/archive/$DATE"
log() { echo "$(date -Is) renouveler: $*"; }

# 0. Faut-il renouveler ? (-checkend rend 0 si le certificat reste valide SEUIL jours)
if [ "${FORCE:-0}" != "1" ] && \
   openssl x509 -checkend $((SEUIL * 86400)) -noout -in "$TLS/serveur_chaine.crt" >/dev/null; then
  log "certificat valide plus de $SEUIL jours : rien a faire"; exit 0
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cd "$PKI"

# 1. Nouvelle cle et nouvelle demande (la cle ne quitte jamais cette machine)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/serveur.key"
openssl req -new -key "$TMP/serveur.key" -subj "/CN=$CN" \
  -addext "subjectAltName=$SAN" -out "$TMP/serveur.csr"

# 2. Signature par l'intermediaire
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$TMP/serveur.csr" -out "$TMP/serveur.crt"
cat "$TMP/serveur.crt" inter/inter.crt > "$TMP/serveur_chaine.crt"

# 3. Verification AVANT tout deploiement : chaine, nom, usage, cle = certificat
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslserver -verify_hostname "$CN" "$TMP/serveur.crt" >/dev/null
[ "$(openssl pkey -in "$TMP/serveur.key" -pubout)" = \
  "$(openssl x509 -in "$TMP/serveur.crt" -pubkey -noout)" ] \
  || { log "ERREUR : la cle ne correspond pas au certificat"; exit 1; }
log "nouvelle chaine verifiee"

# 4a. Sauvegarde de l'ancien certificat et de l'ancienne cle (retour arriere)
mkdir -p "$ARCHIVE"
cp -p "$TLS/serveur.key" "$TLS/serveur_chaine.crt" "$ARCHIVE/"

retour_arriere() {
  log "ECHEC : retour a la version precedente ($ARCHIVE)"
  install -m 600 "$ARCHIVE/serveur.key" "$TLS/serveur.key"
  install -m 644 "$ARCHIVE/serveur_chaine.crt" "$TLS/serveur_chaine.crt"
  $RELOAD_CMD || true
  exit 1
}

# 4b. Installation, test de la configuration, rechargement sans coupure
install -m 600 "$TMP/serveur.key" "$TLS/serveur.key"
install -m 644 "$TMP/serveur_chaine.crt" "$TLS/serveur_chaine.crt"
nginx -t || retour_arriere
$RELOAD_CMD || retour_arriere

# 4c. Controle apres deploiement : le serveur presente bien le nouveau certificat
sleep 1
ATTENDU=$(openssl x509 -in "$TMP/serveur.crt" -noout -fingerprint -sha256)
SERVI=$(openssl s_client -connect "${CIBLE:-127.0.0.1:443}" -servername "$CN" </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256) || SERVI=""
[ "$ATTENDU" = "$SERVI" ] || retour_arriere
log "OK : nouveau certificat en service ($(openssl x509 -in "$TMP/serveur.crt" -noout -enddate))"
