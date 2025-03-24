import csv
import json
import logging
import logging.handlers
import os
import subprocess
import sys

# Configurazione logging
def setup_logger(level):
    logger = logging.getLogger("blockIP_logger")
    logger.propagate = False
    logger.setLevel(level)
    file_handler = logging.handlers.RotatingFileHandler( '/opt/splunk/var/log/splunk/blockIP.log', maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

logger = setup_logger(logging.INFO)

# Configurazione SSH per connettersi alla macchina forwarder
FORWARDER_IP = "10.121.0.232"  # Sostituisci con l'IP della macchina forwarder
SSH_USER = "ubuntu"
SSH_KEY_PATH = "/home/ubuntu/.ssh/id_rsa"
SSH_CMD = f"ssh -i {SSH_KEY_PATH} {SSH_USER}@{FORWARDER_IP}"

# Cartella dove si trovano i CSV
LOOKUPS_DIR = "/opt/splunk/etc/apps/search/lookups"

# Funzione per leggere gli IP o gli utenti dal CSV corretto
def get_block_list(alert_type):
    csv_file_mapping = {
        "ssh_bruteforce": "ssh_bruteforce.csv",
        "syn_scan": "syn_scan.csv",
        "sudo_abuse": "sudo_abuse.csv",
        "sudo_bruteforce": "sudo_bruteforce.csv"
    }
    csv_file = csv_file_mapping.get(alert_type)  # CORRETTO: ora è allineato correttamente
    if not csv_file:
        logger.error(f"Alert type {alert_type} non riconosciuto.")
        return None

    csv_path = os.path.join(LOOKUPS_DIR, csv_file)

    if not os.path.exists(csv_path):
        logger.error(f"Il file {csv_path} non esiste.")
        return None

    blocked_entities = []
    with open(csv_path, mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = "ip" if "ip" in row else "user"
            blocked_entities.append(row[key])

            logger.info(f"Entità da bloccare per {alert_type}: {blocked_entities}")

    return blocked_entities

def block_ip(ip, timeout=2):
    try:
        block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
       # unblock_cmd = f"(sleep {timeout * 60}; sudo iptables -D INPUT -s {ip} -j DROP) &"
        unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"

        full_cmd = f"{SSH_CMD} \"{block_cmd} && echo \"{unblock_cmd}\"| at now + {timeout} minutes \""

        logger.info(f"Comando SSH eseguito: {full_cmd}")
        result = subprocess.run(full_cmd, shell=True, check=True, text=True, capture_output=True)

        logger.info(result)
        logger.info(f"Bloccato IP: {ip} sulla macchina forwarder per {timeout} minuti")
    except subprocess.CalledProcessError as e:
        logger.error(f"Errore nel blocco IP {ip}: {e}")

# Funzione per bloccare un utente per 2 minuti
def block_user(user, timeout=2):
    try:
        block_cmd = f"sudo usermod -L -e 1 {user}"
        unblock_cmd = f"sudo usermod -U -e -1 {user}"
        logout_cmd = f"sudo skill -KILL -u {user}"

        full_cmd = f"{SSH_CMD} \"{logout_cmd} && {block_cmd} && echo \"{unblock_cmd}\" | at now + {timeout} minutes\""
        logger.info(f"Comando SSH eseguito: {full_cmd}")

        result=subprocess.run(full_cmd, shell=True, text=True, check=True, capture_output=True)
        logger.info(result)


        logger.info(f"Bloccato utente: {user} sulla macchina forwarder per {timeout} minuti")
    except subprocess.CalledProcessError as e:
        logger.error(f"Errore nel blocco utente {user}: {e}")

# Funzione principale
def main():
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--execute":
            payload = json.loads(sys.stdin.read())
            logger.info(f"Payload ricevuto: {payload}")


            alert_type = payload.get("configuration", {}).get("listblock") # ← Qui viene letto il valore corretto

            if not alert_type:
                logger.error("Dati mancanti nel payload.")
                return

            blocked_entities = get_block_list(alert_type)

            if not blocked_entities:
                logger.warning("Nessun IP o utente trovato da bloccare.")
                return

            for entity in blocked_entities:
                if alert_type in ["ssh_bruteforce", "syn_scan"]:  # Questi alert bloccano IP
                    block_ip(entity)
                elif alert_type in ["sudo_abuse", "sudo_bruteforce"]:  # Questi alert bloccano utenti
                    block_user(entity)
    except Exception as error:
        logger.info(f"{error}")

if __name__ == "__main__":
    main()

