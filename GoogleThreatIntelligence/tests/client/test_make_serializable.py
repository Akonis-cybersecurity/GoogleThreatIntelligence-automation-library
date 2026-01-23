from googlethreatintelligence.client import VTAPIConnector


def test_make_serializable_prefers_to_dict():
    connector = VTAPIConnector(api_key="dummy")

    class Obj:
        def to_dict(self):
            return {"a": 1}

    assert connector._make_serializable(Obj()) == {"a": 1}


def test_make_serializable_uses_json_attribute():
    connector = VTAPIConnector(api_key="dummy")

    class Obj:
        _json = {"b": 2}

    assert connector._make_serializable(Obj()) == {"b": 2}


def test_make_serializable_falls_back_to_public_dict():
    connector = VTAPIConnector(api_key="dummy")

    class Obj:
        def __init__(self):
            self.a = 1
            self._secret = 2

    assert connector._make_serializable(Obj()) == {"a": 1}


def test_make_serializable_handles_lists_and_depth():
    connector = VTAPIConnector(api_key="dummy")

    assert connector._make_serializable([1, (2, 3)]) == [1, [2, 3]]
    assert connector._make_serializable("x", depth=11, max_depth=10) == "x"
