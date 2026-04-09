"""Tests for explorer.knowledge.fingerprint."""

import json

from kube2docs.knowledge.fingerprint import FingerprintTracker, parse_image_digest


class TestFingerprintTracker:
    def test_new_workload_has_changed(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        assert tracker.has_changed("ns", "app", {"img:v1": "sha1"}, {})

    def test_unchanged_after_set(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        images = {"nginx:1.25": "abc123"}
        configs = {"configmap/app-config": "12345"}
        tracker.set_fingerprint("ns", "app", images, configs)
        assert not tracker.has_changed("ns", "app", images, configs)

    def test_changed_image(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        tracker.set_fingerprint("ns", "app", {"nginx:1.25": "abc"}, {})
        assert tracker.has_changed("ns", "app", {"nginx:1.26": "def"}, {})

    def test_changed_config_version(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        configs_v1 = {"configmap/app": "100"}
        configs_v2 = {"configmap/app": "101"}
        tracker.set_fingerprint("ns", "app", {}, configs_v1)
        assert tracker.has_changed("ns", "app", {}, configs_v2)

    def test_save_and_reload(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        images = {"myimg:latest": "digest1"}
        configs = {"secret/creds": "rv42"}
        tracker.set_fingerprint("prod", "web", images, configs)
        tracker.save()

        # Reload from disk
        tracker2 = FingerprintTracker(tmp_path)
        assert not tracker2.has_changed("prod", "web", images, configs)
        assert tracker2.has_changed("prod", "web", {"myimg:v2": "digest2"}, configs)

    def test_save_creates_file(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        tracker.set_fingerprint("ns", "app", {}, {})
        tracker.save()
        assert (tmp_path / ".fingerprints.json").exists()
        data = json.loads((tmp_path / ".fingerprints.json").read_text())
        assert "ns/app" in data

    def test_get_fingerprint(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        assert tracker.get_fingerprint("ns", "app") is None
        tracker.set_fingerprint("ns", "app", {"img": "d"}, {"cm": "rv1"})
        fp = tracker.get_fingerprint("ns", "app")
        assert fp is not None
        assert fp["images"] == {"img": "d"}
        assert fp["config_versions"] == {"cm": "rv1"}

    def test_remove(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        tracker.set_fingerprint("ns", "app", {}, {})
        assert tracker.remove("ns", "app") is True
        assert tracker.get_fingerprint("ns", "app") is None
        assert tracker.remove("ns", "app") is False

    def test_tracked_workloads(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        tracker.set_fingerprint("ns1", "a", {}, {})
        tracker.set_fingerprint("ns2", "b", {}, {})
        assert sorted(tracker.tracked_workloads()) == ["ns1/a", "ns2/b"]

    def test_workload_key(self, tmp_path):
        assert FingerprintTracker.workload_key("default", "nginx") == "default/nginx"

    def test_corrupt_file_handled(self, tmp_path):
        fp_file = tmp_path / ".fingerprints.json"
        fp_file.write_text("not valid json{{{")
        tracker = FingerprintTracker(tmp_path)
        assert tracker.fingerprints == {}

    def test_multiple_workloads_independent(self, tmp_path):
        tracker = FingerprintTracker(tmp_path)
        tracker.set_fingerprint("ns", "a", {"img:v1": "d1"}, {})
        tracker.set_fingerprint("ns", "b", {"img:v2": "d2"}, {})
        # Change only 'a'
        assert tracker.has_changed("ns", "a", {"img:v3": "d3"}, {})
        assert not tracker.has_changed("ns", "b", {"img:v2": "d2"}, {})


class TestParseImageDigest:
    def test_with_digest(self):
        ref = "nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        assert parse_image_digest(ref) == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    def test_with_tag_and_digest(self):
        ref = "registry.io/app:v1.2@sha256:deadbeef"
        assert parse_image_digest(ref) == "deadbeef"

    def test_without_digest(self):
        assert parse_image_digest("nginx:1.25") is None
        assert parse_image_digest("nginx:latest") is None
        assert parse_image_digest("registry.io/app:v1") is None

    def test_bare_image(self):
        assert parse_image_digest("nginx") is None
