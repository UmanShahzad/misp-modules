import json
import os
from unittest.mock import patch

import pytest
import requests

from misp_modules.modules.expansion import internetdata

# A VPN server on a hosting network, looked up with a key.
VPN = json.loads(
    r"""{"ip":"146.70.116.130","is_bogon":false,"is_vpn":true,"is_tor":false,"is_relay":false,"is_resproxy":false,"is_dcproxy":false,"is_mobproxy":false,"is_pubproxy":false,"is_hosting":true,"is_cdn":false,"is_anycast":false,"is_carrier":false,"is_satellite":false,"is_ssh":false,"is_smtp":false,"is_web":false,"is_dns_resolver":false,"is_bittorrent":false,"location":{"continent":"EU","continent_name":"Europe","country":"AT","country_name":"Austria","timezone":"Europe/Vienna","currency_code":"EUR","currency_name":"Euro","region":"Vienna","region_code":"AT-9","city":"Vienna","postal_code":"1230","latitude":48.20849,"longitude":16.37208,"accuracy_radius":10,"geoname_id":"2761369","dma_code":"","last_changed":"2026-10-06"},"vpn":{"provider":"mullvad","provider_name":"Mullvad","confidence":"high","last_seen":"2026-11-18"},"tor":{},"relay":{},"resproxy":{},"dcproxy":{},"mobproxy":{},"pubproxy":{},"hosting":{"provider":"m247","provider_name":"M247","confidence":"high","last_seen":"2026-11-18"},"cdn":{},"carrier":{},"satellite":{},"ssh":{},"smtp":{},"web":[],"dns_resolver":{},"bittorrent":{},"asn":{"asn":9009,"name":"M247 Europe SRL","domain":"m247global.com","type":"hosting","prefix":"146.70.116.0/24","country":"RO","rpki_status":"not_found"},"company":{"name":"M247 LTD Vienna Infrastructure","domain":"m247.ro","type":"hosting","country":"AT"},"hostname":"","abuse":{"email":"abuse@m247.ro","name":"M247 Europe","phone":"","address":"Sos. Fabrica de Glucoza, Nr 11B, etaj 1, Sector 2, Bucuresti Romania","country":"AT","network":"146.70.116.0-146.70.116.255","validated":false,"unvalidated_since":""},"trial_expired":false}"""  # noqa: E501
)
# A Tor exit looked up without a key: the VPN, hosting, CDN and proxy flags are left out.
TOR_KEYLESS = json.loads(
    r"""{"ip":"185.220.101.1","is_bogon":false,"is_tor":true,"is_relay":false,"is_anycast":false,"is_carrier":false,"is_satellite":false,"is_ssh":false,"is_smtp":false,"is_web":true,"is_dns_resolver":false,"is_bittorrent":false,"location":{"continent":"EU","continent_name":"Europe","country":"DE","country_name":"Germany","timezone":"Europe/Berlin","currency_code":"EUR","currency_name":"Euro"},"tor":{"provider":"","provider_name":"","confidence":"high","last_seen":"2026-11-18"},"relay":{},"asn":{"asn":60729,"name":"Stiftung Erneuerbare Freiheit","domain":"zwiebelfreunde.de","type":"hosting","prefix":"185.220.101.0/24"},"company":{"name":"Artikel10 e.V.","domain":"artikel10.org"},"hostname":"berlin01.tor-exit.artikel10.org","abuse":{"email":"abuse@artikel10.org"}}"""  # noqa: E501
)
# A satellite customer address, looked up with a key.
SATELLITE = json.loads(
    r"""{"ip":"98.97.16.1","is_bogon":false,"is_vpn":false,"is_tor":false,"is_relay":false,"is_resproxy":false,"is_dcproxy":false,"is_mobproxy":false,"is_pubproxy":false,"is_hosting":false,"is_cdn":false,"is_anycast":false,"is_carrier":false,"is_satellite":true,"is_ssh":false,"is_smtp":false,"is_web":false,"is_dns_resolver":false,"is_bittorrent":false,"location":{"continent":"NA","continent_name":"North America","country":"US","country_name":"United States","timezone":"America/New_York","currency_code":"USD","currency_name":"Dollar","region":"Virginia","region_code":"US-VA","city":"Ashburn","postal_code":"20147","latitude":39.04372,"longitude":-77.48749,"accuracy_radius":500,"geoname_id":"4744870","dma_code":"511","last_changed":"2026-10-01"},"vpn":{},"tor":{},"relay":{},"resproxy":{},"dcproxy":{},"mobproxy":{},"pubproxy":{},"hosting":{},"cdn":{},"carrier":{},"satellite":{"provider":"starlink","provider_name":"Starlink","orbit":"leo","segment":"mixed","country":"US","asn":14593,"confidence":"high"},"ssh":{},"smtp":{},"web":[],"dns_resolver":{},"bittorrent":{},"asn":{"asn":14593,"name":"Space Exploration Technologies Corporation","domain":"spacex.com","type":"isp","prefix":"98.97.16.0/23","country":"US","rpki_status":"valid"},"company":{"name":"SpaceX Services, Inc.","domain":"spacex.com","type":"isp","country":"US"},"hostname":"customer.ashnvax2.isp.starlink.com","abuse":{"email":"starlink-abuse@spacex.com","name":"Starlink Abuse","phone":"+1-310-363-6000","address":"1 Rocket Rd, Hawthorne, CA, 90250","country":"US","network":"98.97.16.0-98.97.16.255","validated":false,"unvalidated_since":"2025-03-08"},"trial_expired":false}"""  # noqa: E501
)
AS = json.loads(
    r"""{"asn":13335,"name":"Cloudflare, Inc.","country":"US","registry":"arin","allocated":"2010-07-14","domain":"cloudflare.com"}"""
)
UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


class MockResponse:
    def __init__(self, payload, status_code=200, reason="OK"):
        self.payload = payload
        self.status_code = status_code
        self.reason = reason

    def json(self):
        if self.payload is None:
            raise requests.JSONDecodeError("Expecting value", "", 0)
        return self.payload


def _query(value="146.70.116.130", type_="ip-src", config=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    config = {"api_key": "k"} if config is None else config
    return json.dumps({"module": "internetdata", "attribute": attribute, "config": config})


def _run(response, query=None, **kwargs):
    with patch.object(internetdata.requests, "get", side_effect=[response]) as get:
        result = internetdata.handler(query or _query(**kwargs))
    return result, get


def _objects(result):
    return {obj["name"]: obj for obj in result["results"].get("Object", [])}


def _attributes(misp_object):
    attributes = {}
    for attribute in misp_object["Attribute"]:
        attributes.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return attributes


def _references(misp_object):
    return [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]


def test_vpn_with_key():
    result, get = _run(MockResponse(VPN))

    assert get.call_args.args == ("https://api.internetdata.io/146.70.116.130",)
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer k"
    assert result["results"]["Attribute"][0]["value"] == "146.70.116.130"
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "internetdata-ip"}
    assert _attributes(objects["geolocation"]) == {
        "countrycode": ["AT"],
        "country": ["Austria"],
        "region": ["Vienna"],
        "city": ["Vienna"],
        "zipcode": ["1230"],
        "latitude": [48.20849],
        "longitude": [16.37208],
        "accuracy-radius": ["10"],
    }
    assert _references(objects["geolocation"]) == [(UUID, "locates")]
    assert _attributes(objects["asn"]) == {
        "asn": ["AS9009"],
        "organization": ["M247 Europe SRL"],
        "subnet-announced": ["146.70.116.0/24"],
        "country": ["RO"],
    }
    assert _references(objects["asn"]) == [(UUID, "includes")]
    intelligence = objects["internetdata-ip"]
    assert _attributes(intelligence) == {
        "ip": ["146.70.116.130"],
        "company-name": ["M247 LTD Vienna Infrastructure"],
        "company-domain": ["m247.ro"],
        "company-type": ["hosting"],
        "abuse-email": ["abuse@m247.ro"],
        "abuse-name": ["M247 Europe"],
        "is-vpn": ["1"],
        "vpn-provider": ["Mullvad"],
        "vpn-confidence": ["high"],
        "vpn-last-seen": ["2026-11-18T00:00:00"],
        "is-hosting": ["1"],
        "hosting-provider": ["M247"],
        "hosting-confidence": ["high"],
        "hosting-last-seen": ["2026-11-18T00:00:00"],
    }
    assert intelligence["template_uuid"] == internetdata.INTERNETDATA_TEMPLATE["uuid"]
    assert intelligence["meta-category"] == "network"
    assert not intelligence.get("comment")
    assert _references(intelligence) == [(UUID, "describes")]
    correlating = {a["object_relation"] for a in intelligence["Attribute"] if not a["disable_correlation"]}
    assert correlating == {"ip"}


def test_tor_without_key():
    result, get = _run(MockResponse(TOR_KEYLESS), value="185.220.101.1", type_="ip-dst", config={})

    assert "Authorization" not in get.call_args.kwargs["headers"]
    objects = _objects(result)
    assert _attributes(objects["geolocation"]) == {"countrycode": ["DE"], "country": ["Germany"]}
    intelligence = objects["internetdata-ip"]
    assert _attributes(intelligence) == {
        "ip": ["185.220.101.1"],
        "hostname": ["berlin01.tor-exit.artikel10.org"],
        "company-name": ["Artikel10 e.V."],
        "company-domain": ["artikel10.org"],
        "abuse-email": ["abuse@artikel10.org"],
        "is-tor": ["1"],
        "tor-confidence": ["high"],
        "tor-last-seen": ["2026-11-18T00:00:00"],
        "is-web": ["1"],
    }
    # The flags a keyless answer leaves out must not read as "no".
    assert intelligence["comment"] == internetdata.PARTIAL_COMMENT


def test_satellite():
    result, _ = _run(MockResponse(SATELLITE), value="98.97.16.1")

    attributes = _attributes(_objects(result)["internetdata-ip"])
    assert attributes["is-satellite"] == ["1"]
    assert attributes["satellite-provider"] == ["Starlink"]
    assert attributes["hostname"] == ["customer.ashnvax2.isp.starlink.com"]


def test_carrier():
    carrier = {**SATELLITE, "is_satellite": False, "is_carrier": True, "carrier": {"name": "T-Mobile", "mcc": "310"}}
    result, _ = _run(MockResponse(carrier), value="98.97.16.1")

    attributes = _attributes(_objects(result)["internetdata-ip"])
    assert attributes["is-carrier"] == ["1"]
    assert attributes["carrier-name"] == ["T-Mobile"]
    assert "is-satellite" not in attributes


def test_blank_key_is_keyless():
    _, get = _run(MockResponse(TOR_KEYLESS), value="185.220.101.1", config={"api_key": "  "})

    assert "Authorization" not in get.call_args.kwargs["headers"]


def test_nothing_known_but_the_location_and_network():
    bare = {key: value for key, value in TOR_KEYLESS.items() if key not in ("hostname", "company", "abuse")}
    result, _ = _run(MockResponse({**bare, "is_tor": False, "is_web": False}), value="185.220.101.1", config={})

    assert set(_objects(result)) == {"geolocation", "asn"}


@pytest.mark.parametrize("field", ["trial_expired", "cap_reached"])
def test_keyed_flags_held_back_is_partial(field):
    held = {**VPN, field: True, **{f"is_{flag}": None for flag in internetdata.KEYED_FLAGS}}
    result, _ = _run(MockResponse(held))

    intelligence = _objects(result)["internetdata-ip"]
    assert intelligence["comment"] == internetdata.PARTIAL_COMMENT
    assert "is-vpn" not in _attributes(intelligence)


def test_ipv6():
    _, get = _run(MockResponse(TOR_KEYLESS), value=" 2001:4860:4860::8888 ")

    assert get.call_args.args == ("https://api.internetdata.io/2001:4860:4860::8888",)


@pytest.mark.parametrize("value", ["10.0.0.1", "127.0.0.1", "::1", "192.168.1.1"])
def test_private_address_is_not_looked_up(value):
    with patch.object(internetdata.requests, "get") as get:
        result = internetdata.handler(_query(value=value))
    assert "private or reserved" in result["error"]
    get.assert_not_called()


def test_bogon_answer():
    result, _ = _run(MockResponse({**TOR_KEYLESS, "is_bogon": True}))
    assert "bogon" in result["error"]


@pytest.mark.parametrize("value", ["AS13335", "13335", "as 13335"])
def test_as(value):
    result, get = _run(MockResponse(AS), value=value, type_="AS", config={})

    assert get.call_args.args == ("https://api.internetdata.io/asn/13335",)
    asn = _objects(result)["asn"]
    assert _attributes(asn) == {"asn": ["AS13335"], "organization": ["Cloudflare, Inc."], "country": ["US"]}
    assert _references(asn) == [(UUID, "describes")]


def test_unknown_as():
    unknown = {"asn": 4294967000, "name": "", "country": "", "registry": "", "allocated": "", "domain": ""}
    result, _ = _run(MockResponse(unknown), value="AS4294967000", type_="AS")
    assert result["error"] == "InternetData has no record of AS4294967000."


@pytest.mark.parametrize("value", ["ASX", "AS0", "AS4294967296", "AS-1"])
def test_invalid_as(value):
    with patch.object(internetdata.requests, "get") as get:
        result = internetdata.handler(_query(value=value, type_="AS"))
    assert result["error"] == f"{value} is not a valid AS number."
    get.assert_not_called()


def test_invalid_address():
    result = internetdata.handler(_query(value="not-an-ip"))
    assert result["error"] == "not-an-ip is not a valid IP address."


def test_wrong_type():
    result = internetdata.handler(_query(type_="domain"))
    assert result["error"] == "Wrong input attribute type."


def test_missing_attribute():
    result = internetdata.handler(json.dumps({"module": "internetdata", "config": {}}))
    assert "which should contain at least a type, a value and an uuid" in result["error"]


def test_api_error():
    result, _ = _run(MockResponse({"error": "invalid API key"}, status_code=401, reason="Unauthorized"))
    assert result["error"] == "InternetData API error 401: invalid API key"


def test_api_error_without_json():
    result, _ = _run(MockResponse(None, status_code=502, reason="Bad Gateway"))
    assert result["error"] == "InternetData API error 502: Bad Gateway"


def test_unreachable():
    with patch.object(internetdata.requests, "get", side_effect=requests.ConnectionError("down")):
        result = internetdata.handler(_query())
    assert result["error"] == "Could not reach the InternetData API: down"


def test_handler_without_query():
    assert internetdata.handler() is False


def test_version_and_introspection():
    assert internetdata.version()["config"] == ["api_key"]
    assert internetdata.introspection() == {"input": ["ip-src", "ip-dst", "AS"], "format": "misp_standard"}


@pytest.mark.skipif(not os.environ.get("INTERNETDATA_LIVE"), reason="set INTERNETDATA_LIVE=1 to call the live API")
def test_live_tor_exit():
    query = json.dumps(
        {"module": "internetdata", "attribute": {"type": "ip-src", "value": "185.220.101.1", "uuid": UUID}}
    )
    result = internetdata.handler(query)
    objects = _objects(result)
    assert _attributes(objects["internetdata-ip"])["is-tor"] == ["1"]
    assert _attributes(objects["asn"])["asn"] == ["AS60729"]


@pytest.mark.skipif(not os.environ.get("INTERNETDATA_LIVE"), reason="set INTERNETDATA_LIVE=1 to call the live API")
def test_live_as():
    query = json.dumps({"module": "internetdata", "attribute": {"type": "AS", "value": "AS13335", "uuid": UUID}})
    result = internetdata.handler(query)
    assert _attributes(_objects(result)["asn"])["organization"] == ["Cloudflare, Inc."]
