#!/usr/bin/env python3
"""
ONVIF enumerator.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import socket
import sys
import time
import uuid

import requests
import requests.auth
import defusedxml.ElementTree as SafeET

import conf

# ---------------------------------------------------------------------------
# Generic XML helpers. Everything is looked up by namespace URI + local name
# so we never depend on which prefix a given device happens to use.
# ---------------------------------------------------------------------------

def local_name(tag):
    """Strip the Clark-notation namespace off an element tag, if present."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def children_named(parent, name):
    """Return direct children of `parent` whose local name matches `name`."""
    return [c for c in parent if local_name(c.tag) == name]


def child_named(parent, name):
    """Return the first direct child matching `name`, or None."""
    matches = children_named(parent, name)
    return matches[0] if matches else None


def descendants_named(root, name):
    """Return every descendant (any depth) whose local name matches `name`."""
    return [el for el in root.iter() if local_name(el.tag) == name]


def first_descendant_named(root, name):
    for el in root.iter():
        if local_name(el.tag) == name:
            return el
    return None


def response_body_element(root):
    """Return the single response element inside <Body>, e.g. GetDeviceInformationResponse."""
    body = first_descendant_named(root, "Body")
    if body is None or len(body) == 0:
        return None
    return body[0]


def tag_key(elem):
    """Dict key for an element: local name for known ONVIF/WS namespaces,
    otherwise the namespace is kept in the key (Clark notation) so vendor
    extensions stay distinguishable for fingerprinting instead of silently
    colliding with standard field names.
    """
    if "}" not in elem.tag:
        return elem.tag
    uri, name = elem.tag[1:].split("}", 1)
    if uri in conf.KNOWN_NAMESPACE_URIS:
        return name
    return f"{{{uri}}}{name}"


def xml_to_dict(elem):
    """Convert an element and its descendants into plain dict/list/str data.

    Args: elem - an xml.etree Element, or None.
    Returns: nested dict keyed by tag_key(), text for leaf elements, lists
        for repeated child tags, or None if elem is None.
    """
    if elem is None:
        return None
    children = list(elem)
    if not children:
        text = (elem.text or "").strip()
        if elem.attrib:
            node = {"#text": text} if text else {}
            node.update(elem.attrib)
            return node
        return text
    result = {}
    for child in children:
        key = tag_key(child)
        value = xml_to_dict(child)
        if key in result:
            if not isinstance(result[key], list):
                result[key] = [result[key]]
            result[key].append(value)
        else:
            result[key] = value
    for key, value in elem.attrib.items():
        result[f"@{key}"] = value
    return result


def safe_parse_xml(data):
    """Parse XML with DTDs/external entities/network access disabled (XXE-safe)."""
    return SafeET.fromstring(data)


def build_prefix_map(raw_xml):
    """Best-effort xmlns prefix->namespace map read straight from the raw
    response bytes. ElementTree resolves element/attribute *names* to full
    namespaces but discards prefixes, so QName-valued attribute *values*
    (e.g. an analytics module Type="tt:Foo") can't be resolved from the
    parsed tree. ONVIF responses conventionally declare every namespace on
    the root Envelope, so a document-wide regex scan is accurate in practice.
    """
    return {m[0]: m[1] for m in re.findall(rb'xmlns:([\w.-]+)="([^"]+)"', raw_xml or b"")}


def resolve_qname(value, prefix_map):
    """Resolve a "prefix:local" QName string using a prefix map from build_prefix_map."""
    if ":" not in value:
        return {"namespace": None, "local_name": value}
    prefix, name = value.split(":", 1)
    uri = prefix_map.get(prefix.encode())
    return {"namespace": uri.decode() if uri else None, "local_name": name}


# ---------------------------------------------------------------------------
# SOAP fault handling
# ---------------------------------------------------------------------------

def parse_soap_fault(root):
    """Extract (code, reason) from a SOAP 1.1 or 1.2 Fault, or None if there isn't one."""
    fault = first_descendant_named(root, "Fault")
    if fault is None:
        return None
    code_values = [e.text.strip() for e in fault.iter() if local_name(e.tag) == "Value" and e.text]
    if not code_values:
        faultcode = first_descendant_named(fault, "faultcode")
        code_values = [faultcode.text.strip()] if faultcode is not None and faultcode.text else []
    reason_el = first_descendant_named(fault, "Text") or first_descendant_named(fault, "faultstring")
    reason = reason_el.text.strip() if reason_el is not None and reason_el.text else ""
    return " ".join(code_values) or "Unknown", reason


def classify_fault(code, reason, creds_sent):
    """Map a SOAP fault to one of our result status strings.

    ONVIF devices commonly reuse the same fault (ter:NotAuthorized) for both
    "you must log in" and "you're logged in but lack permission", so we use
    whether credentials were already attached to this request to tell them
    apart; the raw fault code/reason is always kept in the error entry too.
    """
    text = f"{code} {reason}".lower()
    if "notsupported" in text or "notimplemented" in text:
        return "not_supported"
    if "invalidargval" in text or "invalidargs" in text:
        return "invalid_arguments"
    if "notauthorized" in text or "failedauthentication" in text or "failedcheck" in text or "unauthenticated" in text:
        return "permission_denied" if creds_sent else "authentication_required"
    return "soap_fault"


# ---------------------------------------------------------------------------
# SOAP body / WS-Security helpers
# ---------------------------------------------------------------------------

def soap_body(prefix, operation, inner=""):
    if inner:
        return f"<{prefix}:{operation}>{inner}</{prefix}:{operation}>"
    return f"<{prefix}:{operation}/>"


def soap_action(prefix, operation):
    return f"{conf.NS[prefix]}/{operation}"


def build_wsse_header(username, password, clock_offset):
    """Build a WS-Security UsernameToken header using PasswordDigest.

    PasswordDigest = Base64(SHA1(nonce_bytes + created_utf8 + password_utf8)).
    The nonce must be hashed as raw bytes, not as its base64 text.
    """
    nonce = os.urandom(20)
    created = (datetime.datetime.utcnow() + clock_offset).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode("utf-8") + password.encode("utf-8")).digest())
    from xml.sax.saxutils import escape
    return conf.WSSE_HEADER.format(
        username=escape(username),
        digest_type=conf.WSSE_PASSWORD_DIGEST_TYPE,
        password_digest=digest.decode(),
        nonce_type=conf.WSSE_NONCE_ENCODING_TYPE,
        nonce=base64.b64encode(nonce).decode(),
        created=created,
    )


# ---------------------------------------------------------------------------
# ONVIF SOAP client
# ---------------------------------------------------------------------------

class OnvifClient:
    """Holds the HTTP session and authentication state shared across calls to one device."""

    def __init__(self, username, password, verbose):
        self.username = username
        self.password = password
        self.verbose = verbose
        self.session = requests.Session()
        self.verify = True
        self.tls_warning = None
        self.needs_http = False
        self.needs_wsse = False
        self.http_auth = None
        self.clock_offset = datetime.timedelta()
        self.last_raw = b""
        self.errors = []

    def log(self, msg):
        if self.verbose:
            print(msg, file=sys.stderr)

    def set_clock_offset_from_response(self, root):
        """Read GetSystemDateAndTime's UTCDateTime and store the device/local clock delta."""
        data = xml_to_dict(response_body_element(root))
        utc = data.get("UTCDateTime") if isinstance(data, dict) else None
        if not isinstance(utc, dict):
            return
        try:
            date_part, time_part = utc["Date"], utc["Time"]
            device_time = datetime.datetime(
                int(date_part["Year"]), int(date_part["Month"]), int(date_part["Day"]),
                int(time_part["Hour"]), int(time_part["Minute"]), int(time_part["Second"]),
            )
            self.clock_offset = device_time - datetime.datetime.utcnow()
            self.log(f"[*] Device clock offset vs local time: {self.clock_offset}")
        except (KeyError, TypeError, ValueError):
            pass  # unexpected shape; keep offset at zero and use local time for Created

    def _build_http_auth(self, www_authenticate):
        if "digest" in www_authenticate.lower():
            self.log("[*] HTTP authentication challenge: Digest")
            return requests.auth.HTTPDigestAuth(self.username, self.password)
        self.log("[*] HTTP authentication challenge: Basic")
        return requests.auth.HTTPBasicAuth(self.username, self.password)

    def _send(self, xaddr, prefix, operation, body_xml):
        if not xaddr.lower().startswith(("http://", "https://")):
            return None, {"status": "transport_error", "error": f"unsupported URL scheme: {xaddr}"}

        header_xml = ""
        if self.needs_wsse:
            if not (self.username and self.password):
                return None, {"status": "credentials_required"}
            header_xml = build_wsse_header(self.username, self.password, self.clock_offset)

        envelope = conf.SOAP_ENVELOPE.format(header=header_xml, body=body_xml, **conf.NS)
        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{soap_action(prefix, operation)}"',
            "User-Agent": conf.USER_AGENT,
        }
        auth = self.http_auth if self.needs_http else None

        try:
            resp = self.session.post(xaddr, data=envelope.encode("utf-8"), headers=headers,
                                      timeout=conf.HTTP_TIMEOUT, auth=auth, verify=self.verify)
        except requests.exceptions.SSLError as exc:
            if self.verify:
                self.verify = False
                self.tls_warning = str(exc)
                self.log(f"[!] TLS certificate not valid/self-signed, continuing without verification: {exc}")
                return self._send(xaddr, prefix, operation, body_xml)
            return None, {"status": "transport_error", "error": str(exc)}
        except requests.exceptions.Timeout:
            return None, {"status": "timeout"}
        except requests.exceptions.RequestException as exc:
            return None, {"status": "transport_error", "error": str(exc)}

        self.last_raw = resp.content

        if resp.status_code == 401:
            if self.http_auth is not None:
                return None, {"status": "invalid_credentials", "http_status": 401}
            return None, {
                "status": "authentication_required",
                "http_status": 401,
                "http_challenge": True,
                "www_authenticate": resp.headers.get("WWW-Authenticate", ""),
            }
        if resp.status_code == 403:
            return None, {"status": "permission_denied", "http_status": 403}

        try:
            root = safe_parse_xml(resp.content)
        except Exception as exc:
            return None, {"status": "invalid_xml", "http_status": resp.status_code, "error": str(exc)}

        fault = parse_soap_fault(root)
        if fault is not None:
            code, reason = fault
            creds_sent = self.needs_wsse or self.http_auth is not None
            status = classify_fault(code, reason, creds_sent)
            err = {"status": status, "http_status": resp.status_code, "soap_fault_code": code, "soap_fault_reason": reason}
            if status == "authentication_required" and not self.needs_wsse:
                err["wsse_challenge"] = True
            return None, err

        if resp.status_code >= 400:
            return None, {"status": "http_error", "http_status": resp.status_code}

        return root, None

    def call(self, xaddr, prefix, operation, inner="", service="Device"):
        """Invoke one ONVIF SOAP operation, upgrading auth automatically on a first challenge.

        Args: xaddr, SOAP prefix/operation, inner body XML, service label for logging/errors.
        Returns: (root_element, None) on success, or (None, error_dict) on failure.
        """
        body = soap_body(prefix, operation, inner)
        root, err = self._send(xaddr, prefix, operation, body)

        if err and err.get("http_challenge") and not self.needs_http:
            self.needs_http = True
            if self.username and self.password:
                self.http_auth = self._build_http_auth(err.get("www_authenticate", ""))
                root, err = self._send(xaddr, prefix, operation, body)

        if err and err.get("wsse_challenge") and not self.needs_wsse:
            self.log("[*] Authentication required: WS-Security UsernameToken")
            self.needs_wsse = True
            if self.username and self.password:
                root, err = self._send(xaddr, prefix, operation, body)

        if err:
            entry = {k: v for k, v in err.items() if k not in ("http_challenge", "wsse_challenge", "www_authenticate")}
            entry["operation"] = operation
            entry["service"] = service
            self.errors.append(entry)
            self.log(f"[!] {service}.{operation}: {entry['status']}")
            return None, entry

        self.log(f"[*] {service}.{operation}: success")
        return root, None


# ---------------------------------------------------------------------------
# Bootstrap / authentication detection
# ---------------------------------------------------------------------------

def bootstrap_auth(client, device_url):
    """Probe the Device Service to find out whether auth is required, and pick a mechanism.

    Args: client, device_url.
    Returns: (authentication_info_dict, device_info_root_or_None).
    """
    time_root, _ = client.call(device_url, "tds", "GetSystemDateAndTime", service="Device")
    if time_root is not None:
        client.set_clock_offset_from_response(time_root)

    info_root, _ = client.call(device_url, "tds", "GetDeviceInformation", service="Device")

    info = {
        "http_auth": client.needs_http,
        "ws_security": client.needs_wsse,
        "tls_verified": client.verify,
        "credentials_provided": bool(client.username),
    }
    if client.tls_warning:
        info["tls_warning"] = client.tls_warning

    auth_required = client.needs_http or client.needs_wsse
    info["required"] = auth_required

    if info_root is not None:
        info["status"] = "ok"
    elif auth_required and not client.username:
        info["status"] = "credentials_required"
    elif auth_required:
        info["status"] = "invalid_credentials"
    else:
        info["status"] = "unreachable"
    return info, info_root


# ---------------------------------------------------------------------------
# Device service
# ---------------------------------------------------------------------------

def extract_device_info(root):
    return xml_to_dict(response_body_element(root)) or {}


def extract_scopes(root):
    data = xml_to_dict(response_body_element(root)) or {}
    scopes = data.get("Scopes", [])
    return scopes if isinstance(scopes, list) else [scopes]


def detect_conformance_profiles(scopes):
    """Classify ONVIF conformance profiles (Profile S/T/G/M/A/C/...) from scope URIs."""
    profiles = set()
    for scope in scopes:
        item = scope.get("ScopeItem", "") if isinstance(scope, dict) else ""
        match = re.search(r"onvif://www\.onvif\.org/Profile/(\w+)", item)
        if match:
            profiles.add(match.group(1))
    return sorted(profiles)


def parse_service_element(el):
    version_el = child_named(el, "Version")
    major = minor = None
    if version_el is not None:
        major_el, minor_el = child_named(version_el, "Major"), child_named(version_el, "Minor")
        major = major_el.text if major_el is not None else None
        minor = minor_el.text if minor_el is not None else None
    ns_el, xaddr_el, cap_el = child_named(el, "Namespace"), child_named(el, "XAddr"), child_named(el, "Capabilities")
    return {
        "namespace": ns_el.text.strip() if ns_el is not None and ns_el.text else None,
        "xaddr": xaddr_el.text.strip() if xaddr_el is not None and xaddr_el.text else None,
        "version": {"major": major, "minor": minor},
        "capabilities": xml_to_dict(cap_el),
    }


def parse_capabilities_fallback(root):
    """Build a services list from the older GetCapabilities response.

    GetCapabilities groups things by category name rather than namespace, so
    the namespace here is inferred from CAPABILITY_CATEGORY_NAMESPACES rather
    than read off the XML.
    """
    caps_el = first_descendant_named(root, "Capabilities")
    if caps_el is None:
        return []
    extension_el = child_named(caps_el, "Extension")
    services = []
    for category, ns_uri in conf.CAPABILITY_CATEGORY_NAMESPACES.items():
        cat_el = child_named(caps_el, category)
        if cat_el is None and extension_el is not None:
            cat_el = child_named(extension_el, category)
        if cat_el is None:
            continue
        xaddr_el = child_named(cat_el, "XAddr")
        services.append({
            "namespace": ns_uri,
            "xaddr": xaddr_el.text.strip() if xaddr_el is not None and xaddr_el.text else None,
            "version": None,
            "capabilities": xml_to_dict(cat_el),
        })
    return services


def discover_services(client, device_url):
    """List ONVIF services via GetServices, falling back to GetCapabilities."""
    root, _ = client.call(device_url, "tds", "GetServices", '<tds:IncludeCapability>true</tds:IncludeCapability>', service="Device")
    services = [parse_service_element(el) for el in descendants_named(root, "Service")] if root is not None else []
    if not services:
        client.log("[*] GetServices unavailable or empty, falling back to GetCapabilities")
        root, _ = client.call(device_url, "tds", "GetCapabilities", "<tds:Category>All</tds:Category>", service="Device")
        if root is not None:
            services = parse_capabilities_fallback(root)
    return services


def enumerate_device_network(client, device_url):
    """Fetch the remaining read-only Device Service getters (network, users' certs, etc.)."""
    network = {}
    ops = [
        ("GetHostname", "hostname"), ("GetDNS", "dns"), ("GetNTP", "ntp"),
        ("GetNetworkInterfaces", "network_interfaces"), ("GetNetworkProtocols", "network_protocols"),
        ("GetNetworkDefaultGateway", "default_gateway"), ("GetDynamicDNS", "dynamic_dns"),
        ("GetCertificates", "certificates"), ("GetCACertificates", "ca_certificates"),
    ]
    for op, key in ops:
        root, _ = client.call(device_url, "tds", op, service="Device")
        if root is not None:
            network[key] = xml_to_dict(response_body_element(root))
    return network


def enumerate_users(client, device_url):
    root, _ = client.call(device_url, "tds", "GetUsers", service="Device")
    if root is None:
        return []
    users = xml_to_dict(response_body_element(root)).get("User", [])
    return users if isinstance(users, list) else [users]


# ---------------------------------------------------------------------------
# Generic list-operation helper, reused by Media/Media2/PTZ/DeviceIO
# ---------------------------------------------------------------------------

def get_items(client, xaddr, prefix, operation, service, inner=""):
    """Call a list-returning Get operation and normalize its repeated child into a list of dicts."""
    root, _ = client.call(xaddr, prefix, operation, inner, service=service)
    if root is None:
        return []
    data = xml_to_dict(response_body_element(root))
    if not data:
        return []
    items = next(iter(data.values()))
    return items if isinstance(items, list) else [items]


def uri_from_response(root):
    uri_el = first_descendant_named(root, "Uri")
    return uri_el.text.strip() if uri_el is not None and uri_el.text else None


# ---------------------------------------------------------------------------
# Media / Media2 (read-only; RTSP/snapshot URIs are reported, never fetched)
# ---------------------------------------------------------------------------

def enumerate_media(client, xaddr):
    media = {
        "video_sources": get_items(client, xaddr, "trt", "GetVideoSources", "Media"),
        "audio_sources": get_items(client, xaddr, "trt", "GetAudioSources", "Media"),
        "video_source_configurations": get_items(client, xaddr, "trt", "GetVideoSourceConfigurations", "Media"),
        "video_encoder_configurations": get_items(client, xaddr, "trt", "GetVideoEncoderConfigurations", "Media"),
        "audio_source_configurations": get_items(client, xaddr, "trt", "GetAudioSourceConfigurations", "Media"),
        "audio_encoder_configurations": get_items(client, xaddr, "trt", "GetAudioEncoderConfigurations", "Media"),
        "metadata_configurations": get_items(client, xaddr, "trt", "GetMetadataConfigurations", "Media"),
        "profiles": get_items(client, xaddr, "trt", "GetProfiles", "Media"),
    }

    for conf_key, op in (("video_encoder_configurations", "GetVideoEncoderConfigurationOptions"),
                          ("audio_encoder_configurations", "GetAudioEncoderConfigurationOptions")):
        for enc_conf in media[conf_key]:
            token = enc_conf.get("@token")
            if not token:
                continue
            root, _ = client.call(xaddr, "trt", op, f"<trt:ConfigurationToken>{token}</trt:ConfigurationToken>", service="Media")
            if root is not None:
                enc_conf["Options"] = xml_to_dict(response_body_element(root))

    media["stream_uris"], media["snapshot_uris"] = {}, {}
    for profile in media["profiles"]:
        token = profile.get("@token")
        if not token:
            continue
        stream_setup = ('<trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>'
                         '<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>'
                         f'<trt:ProfileToken>{token}</trt:ProfileToken>')
        root, _ = client.call(xaddr, "trt", "GetStreamUri", stream_setup, service="Media")
        if root is not None and uri_from_response(root):
            media["stream_uris"][token] = uri_from_response(root)  # reported only, never connected to

        root, _ = client.call(xaddr, "trt", "GetSnapshotUri", f"<trt:ProfileToken>{token}</trt:ProfileToken>", service="Media")
        if root is not None and uri_from_response(root):
            media["snapshot_uris"][token] = uri_from_response(root)  # reported only, never fetched

    return media


def enumerate_media2(client, xaddr):
    media2 = {
        "profiles": get_items(client, xaddr, "tr2", "GetProfiles", "Media2", "<tr2:Type>All</tr2:Type>"),
        "video_source_configurations": get_items(client, xaddr, "tr2", "GetVideoSourceConfigurations", "Media2"),
        "video_encoder_configurations": get_items(client, xaddr, "tr2", "GetVideoEncoderConfigurations", "Media2"),
        "audio_source_configurations": get_items(client, xaddr, "tr2", "GetAudioSourceConfigurations", "Media2"),
        "audio_encoder_configurations": get_items(client, xaddr, "tr2", "GetAudioEncoderConfigurations", "Media2"),
        "metadata_configurations": get_items(client, xaddr, "tr2", "GetMetadataConfigurations", "Media2"),
    }

    for conf_key, op in (("video_encoder_configurations", "GetVideoEncoderConfigurationOptions"),
                          ("audio_encoder_configurations", "GetAudioEncoderConfigurationOptions")):
        for enc_conf in media2[conf_key]:
            token = enc_conf.get("@token")
            if not token:
                continue
            root, _ = client.call(xaddr, "tr2", op, f"<tr2:ConfigurationToken>{token}</tr2:ConfigurationToken>", service="Media2")
            if root is not None:
                enc_conf["Options"] = xml_to_dict(response_body_element(root))

    media2["stream_uris"], media2["snapshot_uris"] = {}, {}
    for profile in media2["profiles"]:
        token = profile.get("@token")
        if not token:
            continue
        inner = f"<tr2:ProfileToken>{token}</tr2:ProfileToken><tr2:Protocol>RTSP</tr2:Protocol>"
        root, _ = client.call(xaddr, "tr2", "GetStreamUri", inner, service="Media2")
        if root is not None and uri_from_response(root):
            media2["stream_uris"][token] = uri_from_response(root)  # reported only, never connected to

        root, _ = client.call(xaddr, "tr2", "GetSnapshotUri", f"<tr2:ProfileToken>{token}</tr2:ProfileToken>", service="Media2")
        if root is not None and uri_from_response(root):
            media2["snapshot_uris"][token] = uri_from_response(root)  # reported only, never fetched

    return media2


def collect_video_source_tokens(media, media2):
    tokens = {vs["@token"] for vs in media.get("video_sources", []) if vs.get("@token")}
    for cfg in media.get("video_source_configurations", []) + media2.get("video_source_configurations", []):
        if isinstance(cfg, dict) and cfg.get("SourceToken"):
            tokens.add(cfg["SourceToken"])
    return sorted(tokens)


def collect_profile_tokens(media, media2):
    return sorted({p["@token"] for p in media.get("profiles", []) + media2.get("profiles", []) if p.get("@token")})


def collect_analytics_tokens(media, media2):
    """Find existing AnalyticsConfiguration tokens referenced by media profiles (read-only lookup)."""
    tokens = set()
    for profile in media.get("profiles", []):
        cfg = profile.get("AnalyticsConfiguration")
        if isinstance(cfg, dict) and cfg.get("@token"):
            tokens.add(cfg["@token"])
    for profile in media2.get("profiles", []):
        configs = profile.get("Configurations")
        cfg = configs.get("Analytics") if isinstance(configs, dict) else None
        if isinstance(cfg, dict) and cfg.get("@token"):
            tokens.add(cfg["@token"])
    return sorted(tokens)


# ---------------------------------------------------------------------------
# PTZ (read-only: no *Move, no Set/Goto/RemovePreset)
# ---------------------------------------------------------------------------

def enumerate_ptz(client, xaddr, profile_tokens):
    ptz = {"nodes": get_items(client, xaddr, "tptz", "GetNodes", "PTZ"),
           "configurations": get_items(client, xaddr, "tptz", "GetConfigurations", "PTZ")}

    root, _ = client.call(xaddr, "tptz", "GetServiceCapabilities", service="PTZ")
    if root is not None:
        ptz["service_capabilities"] = xml_to_dict(response_body_element(root))

    for pconf in ptz["configurations"]:
        token = pconf.get("@token")
        if not token:
            continue
        root, _ = client.call(xaddr, "tptz", "GetConfigurationOptions", f"<tptz:ConfigurationToken>{token}</tptz:ConfigurationToken>", service="PTZ")
        if root is not None:
            pconf["Options"] = xml_to_dict(response_body_element(root))

    ptz["presets"], ptz["status"], ptz["compatible_configurations"] = {}, {}, {}
    for token in profile_tokens:
        token_xml = f"<tptz:ProfileToken>{token}</tptz:ProfileToken>"

        presets = get_items(client, xaddr, "tptz", "GetPresets", "PTZ", token_xml)
        if presets:
            ptz["presets"][token] = presets

        root, _ = client.call(xaddr, "tptz", "GetStatus", token_xml, service="PTZ")
        if root is not None:
            ptz["status"][token] = xml_to_dict(response_body_element(root))

        compat = get_items(client, xaddr, "tptz", "GetCompatibleConfigurations", "PTZ", token_xml)
        if compat:
            ptz["compatible_configurations"][token] = compat

    return ptz


# ---------------------------------------------------------------------------
# Imaging (read-only: no SetImagingSettings)
# ---------------------------------------------------------------------------

def enumerate_imaging(client, xaddr, video_source_tokens):
    imaging = {"settings": {}, "options": {}, "status": {}}
    root, _ = client.call(xaddr, "timg", "GetServiceCapabilities", service="Imaging")
    if root is not None:
        imaging["service_capabilities"] = xml_to_dict(response_body_element(root))

    for token in video_source_tokens:
        inner = f"<timg:VideoSourceToken>{token}</timg:VideoSourceToken>"
        for op, key in (("GetImagingSettings", "settings"), ("GetOptions", "options"), ("GetStatus", "status")):
            root, _ = client.call(xaddr, "timg", op, inner, service="Imaging")
            if root is not None:
                imaging[key][token] = xml_to_dict(response_body_element(root))
    return imaging


# ---------------------------------------------------------------------------
# Events (read-only: no Subscribe/CreatePullPointSubscription/PullMessages)
# ---------------------------------------------------------------------------

def enumerate_events(client, xaddr):
    events = {}
    root, _ = client.call(xaddr, "tev", "GetServiceCapabilities", service="Events")
    if root is not None:
        events["service_capabilities"] = xml_to_dict(response_body_element(root))
    root, _ = client.call(xaddr, "tev", "GetEventProperties", service="Events")
    if root is not None:
        events["properties"] = xml_to_dict(response_body_element(root))
    return events


# ---------------------------------------------------------------------------
# Analytics (deliberately limited to listing module names/types, per spec)
# ---------------------------------------------------------------------------

def extract_analytics_modules(client, root):
    """Extract analytics Module Name/Type, resolving Type's QName namespace for fingerprinting."""
    prefix_map = build_prefix_map(client.last_raw)
    modules = []
    for mod_el in descendants_named(root, "Module"):
        entry = {"name": mod_el.get("Name")}
        type_value = mod_el.get("Type")
        if type_value is None:
            type_el = child_named(mod_el, "Type")
            type_value = type_el.text.strip() if type_el is not None and type_el.text else None
        if type_value:
            entry["type"] = resolve_qname(type_value, prefix_map)
        modules.append(entry)
    return modules


def enumerate_analytics(client, xaddr, analytics_tokens):
    analytics = {"supported_modules": {}, "configured_modules": {}}
    root, _ = client.call(xaddr, "tan", "GetServiceCapabilities", service="Analytics")
    if root is not None:
        analytics["service_capabilities"] = xml_to_dict(response_body_element(root))

    if not analytics_tokens:
        analytics["note"] = "No existing AnalyticsConfiguration token found via media profiles; module listing skipped."
        return analytics

    for token in analytics_tokens:
        inner = f"<tan:ConfigurationToken>{token}</tan:ConfigurationToken>"
        root, _ = client.call(xaddr, "tan", "GetSupportedAnalyticsModules", inner, service="Analytics")
        if root is not None:
            analytics["supported_modules"][token] = extract_analytics_modules(client, root)

        root, _ = client.call(xaddr, "tan", "GetAnalyticsModules", inner, service="Analytics")
        if root is not None:
            analytics["configured_modules"][token] = extract_analytics_modules(client, root)

    return analytics


# ---------------------------------------------------------------------------
# DeviceIO (read-only: relay outputs/serial ports listed, never activated)
# ---------------------------------------------------------------------------

def enumerate_deviceio(client, xaddr):
    device_io = {}
    root, _ = client.call(xaddr, "tmd", "GetServiceCapabilities", service="DeviceIO")
    if root is not None:
        device_io["service_capabilities"] = xml_to_dict(response_body_element(root))
    for op, key in [("GetVideoSources", "video_sources"), ("GetAudioSources", "audio_sources"),
                     ("GetVideoOutputs", "video_outputs"), ("GetAudioOutputs", "audio_outputs"),
                     ("GetRelayOutputs", "relay_outputs"), ("GetDigitalInputs", "digital_inputs"),
                     ("GetSerialPorts", "serial_ports")]:
        items = get_items(client, xaddr, "tmd", op, "DeviceIO")
        if items:
            device_io[key] = items
    return device_io


# ---------------------------------------------------------------------------
# Recording / Search / Replay
#
# Search's FindRecordings/GetSearchResults flow requires the device to create
# a temporary search session token, so per the safe/read-only requirement it
# is intentionally not implemented here (see README limitations).
# ---------------------------------------------------------------------------

def enumerate_recording(client, xaddr):
    recording = {"recordings": get_items(client, xaddr, "trc", "GetRecordings", "Recording")}
    root, _ = client.call(xaddr, "trc", "GetServiceCapabilities", service="Recording")
    if root is not None:
        recording["service_capabilities"] = xml_to_dict(response_body_element(root))
    return recording


def enumerate_search(client, xaddr):
    search = {}
    root, _ = client.call(xaddr, "tse", "GetServiceCapabilities", service="Search")
    if root is not None:
        search["service_capabilities"] = xml_to_dict(response_body_element(root))
    return search


def enumerate_replay(client, xaddr, recording_tokens):
    replay = {"replay_uris": {}}
    root, _ = client.call(xaddr, "trp", "GetServiceCapabilities", service="Replay")
    if root is not None:
        replay["service_capabilities"] = xml_to_dict(response_body_element(root))
    for token in recording_tokens:
        root, _ = client.call(xaddr, "trp", "GetReplayUri", f"<trp:RecordingToken>{token}</trp:RecordingToken>", service="Replay")
        if root is not None and uri_from_response(root):
            replay["replay_uris"][token] = uri_from_response(root)  # reported only, never connected to
    return replay


# ---------------------------------------------------------------------------
# Fingerprinting index: collect every namespace kept via tag_key()'s
# vendor-extension rule, anywhere in the final result tree.
# ---------------------------------------------------------------------------

def collect_extension_namespaces(obj, found):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key.startswith("{"):
                uri, name = key[1:].split("}", 1)
                found.add((uri, name))
            collect_extension_namespaces(value, found)
    elif isinstance(obj, list):
        for item in obj:
            collect_extension_namespaces(item, found)


# ---------------------------------------------------------------------------
# WS-Discovery
# ---------------------------------------------------------------------------

def parse_probe_match(match_el, source_ip):
    epr_el = first_descendant_named(match_el, "Address")
    types_el, scopes_el, xaddrs_el = child_named(match_el, "Types"), child_named(match_el, "Scopes"), child_named(match_el, "XAddrs")
    return {
        "endpoint_reference": epr_el.text.strip() if epr_el is not None and epr_el.text else None,
        "source_ip": source_ip,
        "xaddrs": xaddrs_el.text.split() if xaddrs_el is not None and xaddrs_el.text else [],
        "types": types_el.text.split() if types_el is not None and types_el.text else [],
        "scopes": scopes_el.text.split() if scopes_el is not None and scopes_el.text else [],
    }


def merge_probe_match(existing, new):
    """Union XAddrs/types/scopes across repeated ProbeMatch replies from the same device."""
    for key in ("xaddrs", "types", "scopes"):
        existing[key] = sorted(set(existing[key]) | set(new[key]))


def run_discovery(args):
    def vlog(msg):
        if args.verbose:
            print(msg, file=sys.stderr)

    vlog(f"[*] Starting WS-Discovery probe on {conf.DISCOVERY_ADDR[0]}:{conf.DISCOVERY_ADDR[1]}")
    probe = conf.WSD_PROBE.format(message_id=str(uuid.uuid4())).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.sendto(probe, conf.DISCOVERY_ADDR)

    devices = {}
    deadline = time.time() + conf.DISCOVERY_TIMEOUT
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            break
        try:
            root = safe_parse_xml(data)
        except Exception:
            continue
        for match in descendants_named(root, "ProbeMatch"):
            parsed = parse_probe_match(match, addr[0])
            key = parsed["endpoint_reference"] or (addr[0], tuple(parsed["xaddrs"]))
            if key in devices:
                merge_probe_match(devices[key], parsed)
            else:
                devices[key] = parsed
                vlog(f"[*] Device found: {parsed['endpoint_reference'] or addr[0]} at {addr[0]}")
    sock.close()

    output_result({"discovery": {"devices": list(devices.values())}}, args)


# ---------------------------------------------------------------------------
# Full ONVIF enumeration
# ---------------------------------------------------------------------------

def output_result(result, args):
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")


def run_enumeration(args):
    result = {
        "target": {"onvif_url": args.onvif_url}, "authentication": {}, "device": {}, "scopes": [],
        "network": {}, "users": [], "services": [], "media": {}, "media2": {}, "imaging": {},
        "ptz": {}, "events": {}, "analytics": {}, "device_io": {}, "recording": {}, "search": {},
        "replay": {}, "extensions": [], "errors": [],
    }

    client = OnvifClient(args.username, args.password, args.verbose)
    client.log(f"[*] Contacting Device Service: {args.onvif_url}")

    auth_info, info_root = bootstrap_auth(client, args.onvif_url)
    result["authentication"] = auth_info

    if auth_info["status"] != "ok":
        reasons = {
            "credentials_required": "Device requires authentication; provide --username/--password.",
            "invalid_credentials": "Authentication failed with the provided credentials.",
            "unreachable": "Could not reach the Device Service.",
        }
        client.log(f"[!] {reasons.get(auth_info['status'], 'Bootstrap failed.')}")
        result["errors"] = client.errors
        output_result(result, args)
        sys.exit(1)

    result["device"] = extract_device_info(info_root)

    scopes_root, _ = client.call(args.onvif_url, "tds", "GetScopes", service="Device")
    scopes = extract_scopes(scopes_root) if scopes_root is not None else []
    result["scopes"] = scopes
    result["device"]["conformance_profiles"] = detect_conformance_profiles(scopes)

    result["services"] = discover_services(client, args.onvif_url)
    client.log(f"[*] GetServices: {len(result['services'])} services discovered")
    result["network"] = enumerate_device_network(client, args.onvif_url)
    result["users"] = enumerate_users(client, args.onvif_url)

    by_ns = {s["namespace"]: s for s in result["services"] if s.get("namespace") and s.get("xaddr")}

    if conf.NS["trt"] in by_ns:
        client.log(f"[*] Enumerating Media: {by_ns[conf.NS['trt']]['xaddr']}")
        result["media"] = enumerate_media(client, by_ns[conf.NS["trt"]]["xaddr"])
    if conf.NS["tr2"] in by_ns:
        client.log(f"[*] Enumerating Media2: {by_ns[conf.NS['tr2']]['xaddr']}")
        result["media2"] = enumerate_media2(client, by_ns[conf.NS["tr2"]]["xaddr"])

    video_source_tokens = collect_video_source_tokens(result["media"], result["media2"])
    profile_tokens = collect_profile_tokens(result["media"], result["media2"])

    if conf.NS["tptz"] in by_ns:
        client.log(f"[*] Enumerating PTZ: {by_ns[conf.NS['tptz']]['xaddr']}")
        result["ptz"] = enumerate_ptz(client, by_ns[conf.NS["tptz"]]["xaddr"], profile_tokens)
    if conf.NS["timg"] in by_ns:
        client.log(f"[*] Enumerating Imaging: {by_ns[conf.NS['timg']]['xaddr']}")
        result["imaging"] = enumerate_imaging(client, by_ns[conf.NS["timg"]]["xaddr"], video_source_tokens)
    if conf.NS["tev"] in by_ns:
        client.log(f"[*] Enumerating Events: {by_ns[conf.NS['tev']]['xaddr']}")
        result["events"] = enumerate_events(client, by_ns[conf.NS["tev"]]["xaddr"])
    if conf.NS["tan"] in by_ns:
        client.log(f"[*] Enumerating Analytics: {by_ns[conf.NS['tan']]['xaddr']}")
        analytics_tokens = collect_analytics_tokens(result["media"], result["media2"])
        result["analytics"] = enumerate_analytics(client, by_ns[conf.NS["tan"]]["xaddr"], analytics_tokens)
    if conf.NS["tmd"] in by_ns:
        client.log(f"[*] Enumerating DeviceIO: {by_ns[conf.NS['tmd']]['xaddr']}")
        result["device_io"] = enumerate_deviceio(client, by_ns[conf.NS["tmd"]]["xaddr"])
    if conf.NS["trc"] in by_ns:
        client.log(f"[*] Enumerating Recording: {by_ns[conf.NS['trc']]['xaddr']}")
        result["recording"] = enumerate_recording(client, by_ns[conf.NS["trc"]]["xaddr"])
    if conf.NS["tse"] in by_ns:
        client.log(f"[*] Enumerating Search: {by_ns[conf.NS['tse']]['xaddr']}")
        result["search"] = enumerate_search(client, by_ns[conf.NS["tse"]]["xaddr"])
    if conf.NS["trp"] in by_ns:
        client.log(f"[*] Enumerating Replay: {by_ns[conf.NS['trp']]['xaddr']}")
        recording_tokens = [r["RecordingToken"] for r in result["recording"].get("recordings", []) if r.get("RecordingToken")]
        result["replay"] = enumerate_replay(client, by_ns[conf.NS["trp"]]["xaddr"], recording_tokens)

    extension_tags = set()
    collect_extension_namespaces(result, extension_tags)
    result["extensions"] = [{"namespace": uri, "local_name": name} for uri, name in sorted(extension_tags)]

    result["errors"] = client.errors
    output_result(result, args)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="ONVIF enumerator (WS-Discovery + SOAP).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print progress to stderr.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-d", "--discovery", action="store_true", help="WS-Discovery only: find ONVIF devices on the LAN.")
    mode.add_argument("-u", "--onvif-url", help="ONVIF Device Service URL to enumerate, e.g. http://host/onvif/device_service")
    parser.add_argument("-U", "--username", help="ONVIF username (requires --password).")
    parser.add_argument("-P", "--password", help="ONVIF password (requires --username).")
    parser.add_argument("-o", "--output", help="Also write the JSON result to this file.")
    args = parser.parse_args()

    if bool(args.username) != bool(args.password):
        parser.error("--username and --password must be provided together.")
    if args.discovery and (args.username or args.password):
        parser.error("--username/--password are not used with --discovery.")
    return args


def main():
    args = parse_args()
    if args.discovery:
        run_discovery(args)
    else:
        run_enumeration(args)


if __name__ == "__main__":
    main()
