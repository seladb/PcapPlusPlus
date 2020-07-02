import pytest

def pytest_addoption(parser):
	parser.addoption("--interface", action="store", help="interface address or name.")

@pytest.fixture
def interface_to_use(request):
	return request.config.getoption("--interface")
