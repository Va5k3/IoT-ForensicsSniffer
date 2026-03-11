import struct
from logger_config import setup_logger

logger = setup_logger("parser")

# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------

MQTT_TYPES: dict = {
    0x10: "CONNECT",
    0x20: "CONNACK",
    0x30: "PUBLISH",
    0x40: "PUBACK",
    0x80: "SUBSCRIBE",
    0xC0: "PINGREQ",
    0xD0: "PINGRESP",
    0xE0: "DISCONNECT",
}


def parse_mqtt(raw: bytes) -> dict | None:
    """
    Parsuje MQTT paket iz sirovih bajtova.
    Vraća dict ili None ako paket nije validan.
    """
    if len(raw) < 2:
        return None

    type_byte = raw[0] & 0xF0
    msg_type  = MQTT_TYPES.get(type_byte, "UNKNOWN")
    # QoS se nalazi u bitovima 2-1 prvog bajta (relevantno samo za PUBLISH)
    qos = (raw[0] & 0x06) >> 1

    result = {
        "msg_type":  msg_type,
        "topic":     "",
        "payload":   "",
        "client_id": "",
        "username":  "",
        "qos":       qos,
    }

    try:
        if type_byte == 0x30:  # PUBLISH
            if len(raw) < 4:
                return result
            topic_len = struct.unpack("!H", raw[2:4])[0]
            topic     = raw[4 : 4 + topic_len].decode("utf-8", errors="replace")

            # ISPRAVKA: QoS > 0 → preskoči 2-bajtni Packet Identifier
            payload_start = 4 + topic_len
            if qos > 0:
                payload_start += 2

            payload = raw[payload_start:].decode("utf-8", errors="replace")
            result["topic"]   = topic
            result["payload"] = payload

        elif type_byte == 0x10:  # CONNECT
            if len(raw) < 10:
                return result
            proto_len = struct.unpack("!H", raw[2:4])[0]
            # 2 (fixed) + 2 (proto_len) + proto_len + 1 (ver) + 1 (flags) + 2 (keepalive)
            offset = 2 + 2 + proto_len + 1 + 1 + 2

            if offset + 2 > len(raw):
                return result

            cid_len   = struct.unpack("!H", raw[offset : offset + 2])[0]
            client_id = raw[offset + 2 : offset + 2 + cid_len].decode("utf-8", errors="replace")
            result["client_id"] = client_id

            # Username (opciono, odmah nakon client_id)
            u_off = offset + 2 + cid_len
            if u_off + 2 <= len(raw):
                u_len = struct.unpack("!H", raw[u_off : u_off + 2])[0]
                result["username"] = raw[u_off + 2 : u_off + 2 + u_len].decode("utf-8", errors="replace")

    except Exception as e:
        logger.debug(f"MQTT parse greška (type=0x{type_byte:02X}): {e}")

    return result


# ---------------------------------------------------------------------------
# CoAP — RFC 7252
# ---------------------------------------------------------------------------

COAP_MSG_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}

COAP_CODES = {
    (0, 0): "EMPTY",   (0, 1): "GET",     (0, 2): "POST",
    (0, 3): "PUT",     (0, 4): "DELETE",
    (2, 1): "Created", (2, 2): "Deleted", (2, 3): "Valid",
    (2, 4): "Changed", (2, 5): "Content",
    (4, 0): "Bad Request",    (4, 1): "Unauthorized",
    (4, 3): "Forbidden",      (4, 4): "Not Found",
    (4, 5): "Method Not Allowed",
    (5, 0): "Internal Server Error", (5, 1): "Not Implemented",
    (5, 2): "Bad Gateway",    (5, 3): "Service Unavailable",
}

_OPT_URI_HOST  = 3
_OPT_URI_PATH  = 11
_OPT_URI_QUERY = 15


def parse_coap(raw: bytes) -> dict | None:
    """
    Parsuje CoAP UDP paket prema RFC 7252.
    Vraća dict kompatibilan sa detektorima ('topic' = URI path).
    """
    if len(raw) < 4:
        return None

    try:
        byte0   = raw[0]
        version = (byte0 >> 6) & 0x03
        if version != 1:
            return None

        msg_type_int = (byte0 >> 4) & 0x03
        tkl          = byte0 & 0x0F

        code_byte   = raw[1]
        code_class  = (code_byte >> 5) & 0x07
        code_detail = code_byte & 0x1F
        code_str    = COAP_CODES.get((code_class, code_detail), f"{code_class}.{code_detail:02d}")

        msg_id = struct.unpack("!H", raw[2:4])[0]

        token_end = 4 + tkl
        if token_end > len(raw):
            return None
        token = raw[4:token_end].hex() if tkl > 0 else ""

        # Parsovanje delta-encoded opcija
        offset        = token_end
        option_number = 0
        uri_path_parts: list = []
        uri_query_parts: list = []
        uri_host = ""

        while offset < len(raw):
            byte = raw[offset]
            if byte == 0xFF:   # payload marker
                offset += 1
                break

            delta_n  = (byte >> 4) & 0x0F
            length_n = byte & 0x0F
            offset  += 1

            # Extended delta
            if delta_n == 13:
                delta = raw[offset] + 13;          offset += 1
            elif delta_n == 14:
                delta = struct.unpack("!H", raw[offset:offset+2])[0] + 269; offset += 2
            elif delta_n == 15:
                break
            else:
                delta = delta_n

            # Extended length
            if length_n == 13:
                opt_len = raw[offset] + 13;        offset += 1
            elif length_n == 14:
                opt_len = struct.unpack("!H", raw[offset:offset+2])[0] + 269; offset += 2
            elif length_n == 15:
                break
            else:
                opt_len = length_n

            option_number += delta
            opt_val  = raw[offset : offset + opt_len]
            offset  += opt_len

            if option_number == _OPT_URI_HOST:
                uri_host = opt_val.decode("utf-8", errors="replace")
            elif option_number == _OPT_URI_PATH:
                uri_path_parts.append(opt_val.decode("utf-8", errors="replace"))
            elif option_number == _OPT_URI_QUERY:
                uri_query_parts.append(opt_val.decode("utf-8", errors="replace"))

        payload   = raw[offset:].decode("utf-8", errors="replace") if offset < len(raw) else ""
        uri_path  = "/" + "/".join(uri_path_parts) if uri_path_parts else ""
        uri_query = "&".join(uri_query_parts)

        return {
            "msg_type":   "COAP",
            "coap_type":  COAP_MSG_TYPES.get(msg_type_int, "UNKNOWN"),
            "code_str":   code_str,
            "code_class": code_class,
            "msg_id":     msg_id,
            "token":      token,
            "uri_host":   uri_host,
            "uri_path":   uri_path,
            "uri_query":  uri_query,
            "topic":      uri_path,    # unified polje (isti interfejs kao MQTT)
            "payload":    payload,
            "client_id":  "",
            "username":   "",
        }

    except Exception as e:
        logger.debug(f"CoAP parse greška: {e}")
        return None


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from reader import load_pcap
    import sys

    pcap = sys.argv[1] if len(sys.argv) > 1 else "captures/normal.pcap"
    data = load_pcap(pcap)

    mqtt_ok = coap_ok = 0
    for p in data:
        if not p["raw"]:
            continue
        if p["protocol"] == "MQTT":
            r = parse_mqtt(p["raw"])
            if r: mqtt_ok += 1
        elif p["protocol"] == "CoAP":
            r = parse_coap(p["raw"])
            if r: coap_ok += 1

    print(f"MQTT parsovano : {mqtt_ok}")
    print(f"CoAP parsovano : {coap_ok}")
