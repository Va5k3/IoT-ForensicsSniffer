from reader import load_pcap
import struct

MQTT_TYPES = { #MQTT poruke su identifikovane po prvom bajtu, koji se naziva "fixed header". Ovaj bajt sadrži informacije o tipu poruke i nekim drugim opcijama. Na osnovu vrijednosti ovog bajta, možemo odrediti o kojoj vrsti MQTT poruke se radi. Primer MQTT poruka izgleda ovako: 102e00064d514973647003c2003c000f6d6f73717075622f3436332d626f7800056571533331000870617373776f7264 - prvi bajt (0x10) označava da se radi o CONNECT poruci, a ostatak bajtova sadrži informacije o klijentu, korisničkom imenu, lozinki i drugim opcijama koje su potrebne za uspostavljanje veze između klijenta i MQTT brokera. Da je prvi bajt bio 0x30, onda bi se radilo o PUBLISH poruci, a ostatak bajtova bi sadržavao informacije o temi, poruci i drugim opcijama koje su potrebne za slanje poruke na MQTT broker.
    0x10 : "CONNECT", #inicijalna poruka kojom se klijent povezuje na MQTT broker
    0x20 : "CONNACK", #odgovor na CONNECT poruku
    0x30 : "PUBLISH", #poruka kojom klijent šalje podatke na MQTT broker
    0x40 : "PUBACK", #odgovor na PUBLISH poruku
    0x80 : "SUBSCRIBE", #poruka kojom klijent traži da se pretplati na određene teme
    0xC0 : "PINGREQ", #poruka kojom klijent provjerava da li je broker još uvijek dostupan
    0xD0 : "PINGRESP", #odgovor na PINGREQ poruku
    0XE0 : "DISCONNECT" #poruka kojom klijent prekida vezu s MQTT brokerom
}


data = load_pcap("captures/scan_A.pcap")

wiht_payload = [p for p in data if len(p['raw'])> 0]
print(f"Paket sa paylodom : {len(wiht_payload)}")

def parse_mqtt(raw : bytes) -> dict | None: #1. izvlacimo tip iz byte 0
    if len(raw) < 2:
        return None
    

    type_byte = raw[0] & 0xF0 #tip poruke se nalazi u prvih 4 bita prvog bajta, pa koristimo bitwise AND operaciju da bismo dobili samo te bitove
    msg_type = MQTT_TYPES.get(type_byte, "UNKNOWN")

    result = {
        "msg_type" : msg_type,
        "topic": "",
        "payload": "",
        "client_id": "",
        "username": "",
    }



    if type_byte == 0x30: #2. za PUBLISH - izvlacimo topik i payload
        topic_len = struct.unpack("!H", raw[2:4])[0]
        topic = raw[4:4+topic_len].decode("utf-8", errors="replace")
        payload = raw[4+topic_len:].decode("utf-8", errors="replace")
        result["topic"] = topic
        result["payload"] = payload
    
    elif type_byte == 0x10: #za CONNECT poruke - izvlacimo client_id

        client_id_len = struct.unpack("!H", raw[10:12])[0] #raw[10:12] - prvi bajt nakon fixed header-a sadrži dužinu client_id-a, a zatim slijedi sam client_id
        client_id = raw[12:12+client_id_len].decode("utf-8", errors="replace")
        result["client_id"] = client_id
        

