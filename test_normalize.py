from datetime import timezone
from collector import dedup_batch, normalize, normalize_url, refang

SAMPLE = {
    "id": 3946051,
    "url": "http://123.8.8.177:41428/bin.sh",
    "url_status": "online",
    "host": "123.8.8.177",
    "date_added": "2026-10-08 07:17:13 UTC",
    "threat": "malware_download",
    "tags": None,
}


def test_sample_record():
    r = normalize(SAMPLE)
    assert r["value"] == "http://123.8.8.177:41428/bin.sh"
    assert r["ioc_type"] == "url" and r["sources"] == ["urlhaus"]
    assert r["tags"] == []                      # null -> []
    assert r["first_seen"].tzinfo == timezone.utc
    assert r["first_seen"].hour == 7
    assert "raw" not in r


def test_host_lowercased_path_preserved():
    assert normalize_url("HTTP://Evil.EXAMPLE.com/Path/AbC?Q=X") == "http://evil.example.com/Path/AbC?Q=X"


def test_refang():
    assert refang("hxxp://evil[.]com/a") == "http://evil.com/a"
    assert normalize_url("  hxxps://evil[.]com/A  ") == "https://evil.com/A"


def test_invalid_records_dropped():
    assert normalize({**SAMPLE, "url": "http:///nohost"}) is None
    assert normalize({**SAMPLE, "url": "not a url"}) is None
    assert normalize({**SAMPLE, "url": None}) is None
    assert normalize({**SAMPLE, "url": "javascript:alert(1)"}) is None


def test_bad_date_does_not_crash():
    assert normalize({**SAMPLE, "date_added": "garbage"}) is not None


def test_dedup_batch_merges_tags():
    a = normalize({**SAMPLE, "tags": ["elf"]})
    b = normalize({**SAMPLE, "tags": ["mips"]})
    out = dedup_batch([a, b])
    assert len(out) == 1 and out[0]["tags"] == ["elf", "mips"]