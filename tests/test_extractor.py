"""Tests for explorer.ai.extractor — local regex parsers."""

from kube2docs.ai.extractor import Extractor


class TestExtractProcessInfo:
    def setup_method(self):
        self.extractor = Extractor()

    def test_nginx_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 root      0:00 nginx: master process nginx -g daemon off;
   28 nginx     0:00 nginx: worker process
   29 nginx     0:00 nginx: worker process
"""
        result = self.extractor.extract_process_info(ps_output, "frontend-abc")
        assert result["language"] == "nginx"
        assert result["runtime"] == "nginx"
        assert "nginx" in result["pid1_command"]

    def test_python_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 root      0:00 python -m http.server 8443
"""
        result = self.extractor.extract_process_info(ps_output, "app-xyz")
        assert result["language"] == "python"

    def test_redis_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 redis     0:02 redis-server *:6379
"""
        result = self.extractor.extract_process_info(ps_output, "redis-abc")
        assert result["language"] == "redis"
        assert result["runtime"] == "redis"

    def test_postgres_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 postgres  0:00 postgres
   63 postgres  0:00 postgres: checkpointer
   64 postgres  0:00 postgres: background writer
"""
        result = self.extractor.extract_process_info(ps_output, "pg-0")
        assert result["language"] == "postgres"

    def test_java_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 app       0:30 java -jar /app/service.jar --server.port=8080
"""
        result = self.extractor.extract_process_info(ps_output, "svc-abc")
        assert result["language"] == "java"
        assert result["runtime"] == "jvm"

    def test_node_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 node      0:10 node /app/server.js
"""
        result = self.extractor.extract_process_info(ps_output, "web-abc")
        assert result["language"] == "node"
        assert result["runtime"] == "node.js"

    def test_unknown_process(self):
        ps_output = """\
PID   USER     TIME  COMMAND
    1 root      0:00 /usr/local/bin/mysterious-binary
"""
        result = self.extractor.extract_process_info(ps_output, "x-abc")
        assert result["language"] == "unknown"


class TestExtractListeners:
    def setup_method(self):
        self.extractor = Extractor()

    def test_netstat_output(self):
        output = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1/nginx: master pro
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1/nginx: master pro
"""
        result = self.extractor.extract_listeners(output, "web-abc")
        ports = {r["port"] for r in result}
        assert 80 in ports
        assert 443 in ports
        # Check process extraction
        for entry in result:
            if entry["port"] == 80:
                assert "nginx" in entry.get("process", "")

    def test_postgres_listener(self):
        output = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN      -
tcp        0      0 :::5432                 :::*                    LISTEN      -
"""
        result = self.extractor.extract_listeners(output, "pg-0")
        assert len(result) >= 1
        assert result[0]["port"] == 5432

    def test_empty_output(self):
        result = self.extractor.extract_listeners("", "pod")
        assert result == []


class TestExtractConnections:
    def setup_method(self):
        self.extractor = Extractor()

    def test_netstat_established(self):
        output = """\
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 10.244.1.5:42130        10.96.189.63:6379       ESTABLISHED 1/app
tcp        0      0 10.244.1.5:38200        10.96.87.208:5432       ESTABLISHED 1/app
"""
        services = [
            {"name": "redis", "namespace": "app-team", "clusterIP": "10.96.189.63"},
            {"name": "postgres", "namespace": "app-team", "clusterIP": "10.96.87.208"},
        ]
        result = self.extractor.extract_connections(output, "api-abc", services)
        assert len(result) == 2
        # Should match services by IP
        matched = {r["matched_service"] for r in result}
        assert "redis.app-team" in matched
        assert "postgres.app-team" in matched

    def test_protocol_guessing(self):
        output = """\
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 10.0.0.1:55000          10.0.0.2:5432           ESTABLISHED
"""
        result = self.extractor.extract_connections(output, "app", [])
        assert len(result) == 1
        assert result[0]["protocol_guess"] == "PostgreSQL"

    def test_empty_connections(self):
        output = """\
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
"""
        result = self.extractor.extract_connections(output, "app", [])
        assert result == []


class TestExtractEnv:
    def setup_method(self):
        self.extractor = Extractor()

    def test_standard_env(self):
        output = "HOME=/root\nPATH=/usr/bin:/bin\nDATABASE_URL=postgresql://db:5432/app\n"
        result = self.extractor.extract_env(output)
        names = {r["name"] for r in result}
        assert "HOME" in names
        assert "DATABASE_URL" in names

    def test_values_are_hashed(self):
        output = "SECRET_KEY=mysecret123\n"
        result = self.extractor.extract_env(output)
        assert len(result) == 1
        # Value should be a 64-char hex hash, not the plaintext
        assert result[0]["value_hash"] != "mysecret123"
        assert len(result[0]["value_hash"]) == 64

    def test_sensitive_detection(self):
        output = "API_KEY=abc\nLOG_LEVEL=debug\n"
        result = self.extractor.extract_env(output)
        by_name = {r["name"]: r for r in result}
        assert by_name["API_KEY"]["sensitive"] is True
        assert by_name["LOG_LEVEL"]["sensitive"] is False

    def test_empty_input(self):
        assert self.extractor.extract_env("") == []


class TestExtractDiskUsage:
    def setup_method(self):
        self.extractor = Extractor()

    def test_df_output(self):
        output = """\
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           64M     0   64M   0% /dev
/dev/sda2       98G   24G   69G  26% /etc/hosts
shm             64M     0   64M   0% /dev/shm
"""
        result = self.extractor.extract_disk_usage(output)
        assert len(result) >= 2
        assert result[0]["mounted_on"] == "/dev"


class TestExtractHealthResponse:
    def setup_method(self):
        self.extractor = Extractor()

    def test_healthy_ok(self):
        r = self.extractor.extract_health_response("OK", "http://localhost/health")
        assert r["status"] == "healthy"

    def test_healthy_json(self):
        r = self.extractor.extract_health_response('{"status": "healthy"}', "http://localhost/healthz")
        assert r["status"] == "healthy"

    def test_unknown_response(self):
        r = self.extractor.extract_health_response("error 503", "http://localhost/health")
        assert r["status"] == "unknown"

    def test_body_truncated(self):
        long_body = "x" * 500
        r = self.extractor.extract_health_response(long_body, "http://localhost/")
        assert len(r["body_snippet"]) == 200


class TestDetectMetrics:
    def setup_method(self):
        self.extractor = Extractor()

    def test_prometheus_metrics(self):
        body = """\
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET"} 1234
"""
        r = self.extractor.detect_metrics(body)
        assert r["prometheus"] is True
        assert r["metric_families"] >= 1

    def test_non_metrics(self):
        r = self.extractor.detect_metrics("<html>Hello</html>")
        assert r["prometheus"] is False


class TestExtractConfigFile:
    def setup_method(self):
        self.extractor = Extractor()

    def test_yaml_detection(self):
        r = self.extractor.extract_config_file("key: value\n", "/etc/app/config.yaml")
        assert r["format"] == "yaml"

    def test_ini_detection(self):
        content = "[section]\nhost = localhost\nport = 5432\n"
        r = self.extractor.extract_config_file(content, "/etc/app.conf")
        assert r["format"] == "ini"
        keys = [f["key"] for f in r["key_fields"]]
        assert "host" in keys

    def test_sensitive_key_flagged(self):
        content = "password = secret123\nhost = localhost\n"
        r = self.extractor.extract_config_file(content, "/etc/app.conf")
        by_key = {f["key"]: f for f in r["key_fields"]}
        assert by_key["password"]["sensitive"] is True
        assert by_key["host"]["sensitive"] is False
