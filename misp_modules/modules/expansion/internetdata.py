import ipaddress
import json
import re

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst", "AS"], "format": "misp_standard"}
moduleinfo = {
    "version": 1,
    "author": "InternetData",
    "description": (
        "An expansion and hover module to look up an IP address or an AS with InternetData: its location, network,"
        " the organization it is registered to, its abuse contact, and Tor, relay, VPN, proxy, hosting, anycast,"
        " carrier and satellite detection. No API key is needed."
    ),
    "module-type": ["expansion", "hover"],
    "name": "InternetData Lookup",
    "logo": "internetdata.png",
    "requirements": [
        "An InternetData API key (optional: without one the API answers everything but the VPN, hosting, CDN and"
        " proxy flags and the city-level location)"
    ],
    "features": (
        "The module takes an IP address or an AS attribute as input and looks it up with the"
        " [InternetData API](https://internetdata.io/api).\n\nFor an IP address it returns a geolocation object, an"
        " asn object with the announced prefix, and an internetdata-ip object with the address's reverse DNS"
        " hostname, the organization it is registered to, its abuse contact and the detection flags that are set,"
        " each with its provider where one is known, its confidence and the date the address was last seen as such."
        " For an AS it returns an asn object with its name and country.\n\nThe `api_key` is optional. Without one"
        " the API answers the country, the network, the organization, the hostname, the abuse email, and the Tor,"
        " privacy relay, anycast, mobile carrier, satellite, SSH, SMTP, web, DNS resolver and BitTorrent flags. With"
        " a key it also answers the VPN, hosting, CDN and residential, datacenter, mobile and public proxy flags"
        " with their providers, and the city, region and coordinates. The key is sent in the Authorization header."
        " Private and reserved addresses are not looked up. Terms: https://internetdata.io/terms, privacy:"
        " https://internetdata.io/privacy."
    ),
    "references": ["https://internetdata.io/api", "https://docs.internetdata.io"],
    "input": "An IP address attribute (ip-src or ip-dst), or an AS attribute.",
    "output": (
        "For an IP address, a geolocation object, an asn object, and an internetdata-ip object with the hostname,"
        " the organization, the abuse contact and the detection flags that are set. For an AS, an asn object."
    ),
}
moduleconfig = ["api_key"]

API_URL = "https://api.internetdata.io/"
TIMEOUT = 10
USER_AGENT = "misp-modules-internetdata/1"

# The internetdata-ip template (MISP/misp-objects), described here for PyMISP releases that do not ship it yet:
# MISP refuses to create an object without its meta-category and template UUID.
INTERNETDATA_TEMPLATE = {
    "uuid": "c73f5bf4-2c49-44c2-a38c-301718fff3db",
    "version": 1,
    "meta-category": "network",
    "description": (
        "IP address intelligence from InternetData: VPN, privacy relay, Tor, hosting, CDN and residential, "
        "datacenter, mobile and public proxy detection, each with the provider where one is known, a "
        "confidence and the date the address was last seen as such; anycast, mobile carrier, satellite and "
        "the services it runs; its reverse DNS hostname, the organization it is registered to and its abuse "
        "contact."
    ),
}
# Without a key, once a free key's trial is spent, or past the organization's overage cap, these flags are left
# out: that must not read as a clean address.
KEYED_FLAGS = ("vpn", "hosting", "cdn", "resproxy", "dcproxy", "mobproxy", "pubproxy")
PARTIAL_COMMENT = (
    "Partial InternetData answer (no API key, a free key's trial is spent, or the organization's overage cap is"
    " reached): the VPN, hosting, CDN and proxy flags are not included"
)
DETECTIONS = ("tor", "relay") + KEYED_FLAGS
SERVICES = ("anycast", "carrier", "satellite", "ssh", "smtp", "web", "dns_resolver", "bittorrent")
AS_NUMBER = re.compile(r"^(?:AS)?\s*(\d{1,10})$", re.IGNORECASE)


class InternetDataError(Exception):
    """A lookup failed with a message that can be shown to the MISP user."""


def lookup(path, api_key):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"  # never in the URL, where it would end up in logs
    try:
        response = requests.get(API_URL + path, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise InternetDataError(f"Could not reach the InternetData API: {e}")
    try:
        data = response.json()
    except ValueError:
        data = None
    if response.status_code != 200:
        message = data.get("error") if isinstance(data, dict) else None
        raise InternetDataError(f"InternetData API error {response.status_code}: {message or response.reason}")
    if not isinstance(data, dict):
        raise InternetDataError("The InternetData API returned a response that is not a JSON object.")
    return data


def _text(value):
    return value if isinstance(value, (str, int, float)) and not isinstance(value, bool) and value != "" else None


def _dict(data, key):
    return data.get(key) if isinstance(data.get(key), dict) else {}


def _details(data):
    """The internetdata-ip attributes the answer holds: who the address belongs to, then each flag that is set."""
    details = []
    company, abuse = _dict(data, "company"), _dict(data, "abuse")
    for value, relation, attribute_type in (
        (data.get("hostname"), "hostname", "hostname"),
        (company.get("name"), "company-name", "text"),
        (company.get("domain"), "company-domain", "domain"),
        (company.get("type"), "company-type", "text"),
        (abuse.get("email"), "abuse-email", "email"),
        (abuse.get("name"), "abuse-name", "text"),
    ):
        if (value := _text(value)) is not None:
            details.append((relation, value, attribute_type))
    for flag in DETECTIONS:
        if data.get(f"is_{flag}") is not True:
            continue
        details.append((f"is-{flag}", 1, "boolean"))
        detail = _dict(data, flag)
        provider = _text(detail.get("provider_name")) or _text(detail.get("provider"))
        if provider is not None and flag != "tor":
            details.append((f"{flag}-provider", provider, "text"))
        if (confidence := _text(detail.get("confidence"))) is not None:
            details.append((f"{flag}-confidence", confidence, "text"))
        if (last_seen := _text(detail.get("last_seen"))) is not None:
            details.append((f"{flag}-last-seen", last_seen, "datetime"))
    for flag in SERVICES:
        if data.get(f"is_{flag}") is True:
            details.append((f"is-{flag.replace('_', '-')}", 1, "boolean"))
    if data.get("is_carrier") is True and (name := _text(_dict(data, "carrier").get("name"))) is not None:
        details.append(("carrier-name", name, "text"))
    satellite = _dict(data, "satellite")
    if data.get("is_satellite") is True:
        if (provider := _text(satellite.get("provider_name")) or _text(satellite.get("provider"))) is not None:
            details.append(("satellite-provider", provider, "text"))
    return details


def _event(attribute):
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)
    return misp_event, input_attribute


def _results(misp_event):
    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


def build_ip_results(attribute, ip, data):
    misp_event, input_attribute = _event(attribute)

    location = _dict(data, "location")
    geolocation = MISPObject("geolocation")
    for key, relation in (
        ("country", "countrycode"),
        ("country_name", "country"),
        ("region", "region"),
        ("city", "city"),
        ("postal_code", "zipcode"),
        ("latitude", "latitude"),
        ("longitude", "longitude"),
        ("accuracy_radius", "accuracy-radius"),
    ):
        if (value := _text(location.get(key))) is not None:
            geolocation.add_attribute(relation, value)
    if geolocation.attributes:
        geolocation.add_reference(input_attribute.uuid, "locates")
        misp_event.add_object(geolocation)

    network = _dict(data, "asn")
    if (number := _text(network.get("asn"))) is not None:
        asn = MISPObject("asn")
        asn.add_attribute("asn", f"AS{number}")
        for key, relation in (("name", "organization"), ("prefix", "subnet-announced"), ("country", "country")):
            if (value := _text(network.get(key))) is not None:
                asn.add_attribute(relation, value)
        asn.add_reference(input_attribute.uuid, "includes")
        misp_event.add_object(asn)

    details = _details(data)
    if details:
        intelligence = MISPObject("internetdata-ip")
        if getattr(intelligence, "template_uuid", None) is None:
            intelligence.template_uuid = INTERNETDATA_TEMPLATE["uuid"]
            intelligence.template_version = INTERNETDATA_TEMPLATE["version"]
            intelligence.description = INTERNETDATA_TEMPLATE["description"]
            setattr(intelligence, "meta-category", INTERNETDATA_TEMPLATE["meta-category"])
        if any(data.get(f"is_{flag}") is None for flag in KEYED_FLAGS):
            intelligence.comment = PARTIAL_COMMENT
        intelligence.add_attribute("ip", str(ip), type="ip-src")
        # Hostnames, organizations, contacts, flags and providers are shared by many unrelated addresses: only the
        # IP correlates.
        for relation, value, attribute_type in details:
            intelligence.add_attribute(relation, value, type=attribute_type, disable_correlation=True)
        intelligence.add_reference(input_attribute.uuid, "describes")
        misp_event.add_object(intelligence)

    return _results(misp_event)


def build_as_results(attribute, data):
    misp_event, input_attribute = _event(attribute)
    asn = MISPObject("asn")
    asn.add_attribute("asn", f"AS{data['asn']}")
    for key, relation in (("name", "organization"), ("country", "country")):
        if (value := _text(data.get(key))) is not None:
            asn.add_attribute(relation, value)
    asn.add_reference(input_attribute.uuid, "describes")
    misp_event.add_object(asn)
    return _results(misp_event)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request.get("attribute")
    if not attribute or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    api_key = ((request.get("config") or {}).get("api_key") or "").strip()
    value = str(attribute["value"]).strip()

    if attribute["type"] == "AS":
        match = AS_NUMBER.match(value)
        if not match or not 0 < int(match.group(1)) < 2**32:
            return {"error": f"{value} is not a valid AS number."}
        try:
            data = lookup(f"asn/{int(match.group(1))}", api_key)
        except InternetDataError as e:
            return {"error": str(e)}
        if not any(_text(data.get(key)) is not None for key in ("name", "country", "registry")):
            return {"error": f"InternetData has no record of AS{int(match.group(1))}."}
        return build_as_results(attribute, data)

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {"error": f"{value} is not a valid IP address."}
    if not ip.is_global:
        return {"error": f"{ip} is a private or reserved address and cannot be looked up."}
    try:
        data = lookup(str(ip), api_key)
    except InternetDataError as e:
        return {"error": str(e)}
    if data.get("is_bogon"):
        return {"error": f"InternetData reports {ip} as a bogon: a private or reserved address."}
    return build_ip_results(attribute, ip, data)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
