#!/usr/bin/env python3
"""surveiller.py - supervision des dates d'expiration des certificats.

Usage : surveiller.py [dossier]   (defaut : /etc/nginx/tls)
Code de sortie : 0 = tout OK, 1 = au moins une ALERTE, 2 = au moins un CRITIQUE
(compatible Nagios / Zabbix / Prometheus textfile / cron).
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

SEUIL_ALERTE, SEUIL_CRITIQUE = 30, 7
NIVEAUX = ("OK", "ALERTE", "CRITIQUE")


def fin_validite(cert: x509.Certificate) -> datetime:
    try:                                  # cryptography >= 42
        return cert.not_valid_after_utc
    except AttributeError:                # anciennes versions
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def lire_certificats(chemin: Path):
    """Rend tous les certificats d'un fichier (PEM multi-certificats ou DER)."""
    donnees = chemin.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in donnees:
        return x509.load_pem_x509_certificates(donnees)
    return [x509.load_der_x509_certificate(donnees)]


def niveau(jours: int) -> int:
    if jours < SEUIL_CRITIQUE:            # inclut les certificats deja expires
        return 2
    if jours < SEUIL_ALERTE:
        return 1
    return 0


def main(dossier: str) -> int:
    maintenant = datetime.now(timezone.utc)
    pire = 0
    for chemin in sorted(Path(dossier).iterdir()):
        if chemin.suffix not in (".crt", ".pem", ".cer", ".der") or not chemin.is_file():
            continue
        try:
            certs = lire_certificats(chemin)
        except ValueError:                # cle privee, CRL, fichier illisible
            continue
        for c in certs:
            jours = (fin_validite(c) - maintenant).days
            n = niveau(jours)
            pire = max(pire, n)
            cn = c.subject.rfc4514_string()
            print(f"{NIVEAUX[n]:9} {jours:5d} j  {chemin.name}  [{cn}]")
    return pire


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/etc/nginx/tls"))
