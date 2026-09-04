import re
import logging
from collections import Counter


# =========================
# Configuration du logging
# =========================

logging.basicConfig(
    filename="analyse.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# =========================
# Lecture du fichier de log
# =========================

with open("log.txt") as fichier:
    texte = fichier.read()


# =========================
# Compter les événements
# =========================

warnings = 0
errors = 0
failed = 0

for ligne in texte.splitlines():
    if "WARNING" in ligne:
        warnings += 1

    if "ERROR" in ligne:
        errors += 1

    if "failed" in ligne.lower():
        failed += 1


print("WARNING :", warnings)
print("ERROR :", errors)
print("FAILED :", failed)


# =========================
# Détecter les IP répétées
# =========================

ips = re.findall(
    r"\d+\.\d+\.\d+\.\d+",
    texte
)

compteurs_ips = Counter(ips)

for ip, nombre in compteurs_ips.items():
    if nombre >= 2:
        print(
            f"IP suspecte : {ip} — "
            f"{nombre} occurrences"
        )

        logging.warning(
            f"IP suspecte détectée : {ip} — "
            f"{nombre} occurrences"
        )


# =========================
# Détecter les failed logins
# =========================

failed_logins = re.findall(
    r"Failed login from (\d+\.\d+\.\d+\.\d+)",
    texte
)

compteurs_logins = Counter(failed_logins)

for ip, nombre in compteurs_logins.items():
    if nombre >= 2:
        print(
            f"IP suspecte pour connexions échouées : "
            f"{ip} — {nombre} tentatives"
        )

        logging.warning(
            f"Connexions échouées : "
            f"{ip} — {nombre} tentatives"
        )


# =========================
# Détecter les erreurs répétées
# =========================

erreurs = re.findall(
    r"ERROR (.+)",
    texte
)

compteurs_erreurs = Counter(erreurs)

for erreur, nombre in compteurs_erreurs.items():
    if nombre >= 2:
        print(
            f"Erreur répétée : "
            f"{erreur} — {nombre} occurrences"
        )

        logging.warning(
            f"Erreur répétée : "
            f"{erreur} — {nombre} occurrences"
        )


# =========================
# Détecter les patterns suspects
# =========================

patterns_suspects = re.findall(
    r".*(?i:unauthorized|denied|attack|intrusion).*",
    texte
)

for ligne in patterns_suspects:
    print(
        f"Pattern suspect détecté : {ligne}"
    )

    logging.warning(
        f"Pattern suspect détecté : {ligne}"
    )
# test hook
