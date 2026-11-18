import pytest
@pytest.fixture(autouse=True)
def reset():
    yield
