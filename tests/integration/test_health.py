"""Integration tests for gRPC health checking service."""

from grpc_health.v1 import health_pb2


def test_health_check_serving(health_stub):
    response = health_stub.Check(health_pb2.HealthCheckRequest(service=""))
    assert response.status == health_pb2.HealthCheckResponse.SERVING
