"""Constants, XML namespaces and SOAP/WS-Discovery templates for onvif-enumerator.py.
Kept separate from the main script so the enumeration logic isn't buried in XML.
"""

USER_AGENT = "onvif-enumerator/1.0"

HTTP_TIMEOUT = 8          # seconds per HTTP request
DISCOVERY_TIMEOUT = 5     # seconds to listen for WS-Discovery ProbeMatch replies
DISCOVERY_ADDR = ("239.255.255.250", 3702)  # standard WS-Discovery multicast address/port

# XML namespaces used to build outgoing requests and to identify elements/
# services in responses by namespace URI. Keys double as the XML prefixes
# used in our own outgoing SOAP envelopes.
NS = {
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsdd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
    "tr2": "http://www.onvif.org/ver20/media/wsdl",
    "timg": "http://www.onvif.org/ver20/imaging/wsdl",
    "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
    "tev": "http://www.onvif.org/ver10/events/wsdl",
    "tan": "http://www.onvif.org/ver20/analytics/wsdl",
    "tmd": "http://www.onvif.org/ver10/deviceIO/wsdl",
    "trc": "http://www.onvif.org/ver10/recording/wsdl",
    "tse": "http://www.onvif.org/ver10/search/wsdl",
    "trp": "http://www.onvif.org/ver10/replay/wsdl",
    "dn": "http://www.onvif.org/ver10/network/wsdl",
}

# Namespaces treated as "known" when converting XML to dicts. Anything else
# is assumed to be a vendor/proprietary extension and gets its namespace URI
# preserved in the output key for fingerprinting (see xml_to_dict/tag_key).
KNOWN_NAMESPACE_URIS = set(NS.values()) | {
    "http://www.w3.org/2003/05/soap-envelope",
    "http://schemas.xmlsoap.org/soap/envelope/",
    "http://www.w3.org/2001/XMLSchema-instance",
    "http://www.w3.org/2001/XMLSchema",
}

# GetCapabilities (fallback, pre-GetServices API) reports capabilities by
# category name instead of namespace URI, so we map the category names we
# care about back to the namespace they correspond to.
CAPABILITY_CATEGORY_NAMESPACES = {
    "Device": NS["tds"],
    "Media": NS["trt"],
    "PTZ": NS["tptz"],
    "Imaging": NS["timg"],
    "Events": NS["tev"],
    "Analytics": NS["tan"],
    "DeviceIO": NS["tmd"],
}

WSSE_PASSWORD_DIGEST_TYPE = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
)
WSSE_NONCE_ENCODING_TYPE = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

# Full SOAP 1.2 envelope. All service namespaces are pre-declared so any
# operation body can just use its own prefix without extra bookkeeping.
SOAP_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="{tds}" xmlns:tt="{tt}" xmlns:trt="{trt}" xmlns:tr2="{tr2}"
            xmlns:timg="{timg}" xmlns:tptz="{tptz}" xmlns:tev="{tev}" xmlns:tan="{tan}"
            xmlns:tmd="{tmd}" xmlns:trc="{trc}" xmlns:tse="{tse}" xmlns:trp="{trp}"
            xmlns:wsse="{wsse}" xmlns:wsu="{wsu}">
<s:Header>{header}</s:Header>
<s:Body>{body}</s:Body>
</s:Envelope>"""

# WS-Security UsernameToken header with PasswordDigest. Placeholders are
# filled in by build_wsse_header() in the main script.
WSSE_HEADER = """<wsse:Security s:mustUnderstand="1">
<wsse:UsernameToken>
<wsse:Username>{username}</wsse:Username>
<wsse:Password Type="{digest_type}">{password_digest}</wsse:Password>
<wsse:Nonce EncodingType="{nonce_type}">{nonce}</wsse:Nonce>
<wsu:Created>{created}</wsu:Created>
</wsse:UsernameToken>
</wsse:Security>"""

# WS-Discovery Probe, targeting the ONVIF NetworkVideoTransmitter device type.
WSD_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<e:Header>
<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
<a:MessageID>uuid:{message_id}</a:MessageID>
<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
</e:Header>
<e:Body>
<w:Probe>
<w:Types>dn:NetworkVideoTransmitter</w:Types>
</w:Probe>
</e:Body>
</e:Envelope>"""
