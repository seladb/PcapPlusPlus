import pytest

def pytest_addoption(parser):
	parser.addoption("--interface", action="store", help="interface address or name.")

@pytest.fixture
def interface_to_use(request):
	return request.config.getoption("--interface")


def pytest_configure(config):
    config.addinivalue_line("markers", "interface_needed: mark test as need interface IP or name from command line")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--interface"):
        # --interface given in cli: do not skip tests
        return
    skip_no_interface = pytest.mark.skip(reason="need --interface option to run")
    for item in items:
        if "interface_needed" in item.keywords:
            item.add_marker(skip_no_interface)