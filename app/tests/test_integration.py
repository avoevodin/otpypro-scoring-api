import hashlib
from datetime import datetime

import pytest

from app import api
from app.store import Store


@pytest.fixture(scope="module")
def server():
    class Dummy:
        context = {}
        headers = {}
        store = Store()

        @staticmethod
        def set_valid_auth(request):
            method_request = api.MethodRequest(request, "method")
            method_request.validate()
            if method_request.errors:
                return method_request.errors, api.INVALID_REQUEST
            request["token"] = api.generate_token(method_request)

        def get_response(self, req):
            self.set_valid_auth(req)
            return api.method_handler(
                {"body": req, "headers": self.headers}, self.context, self.store
            )

    return Dummy()


@pytest.mark.parametrize(
    "args",
    [
        {
            "phone": 72334567837,
            "email": "ema@il.com",
        },
        {
            "first_name": "Mike",
            "last_name": "Smith",
        },
        {
            "gender": 1,
            "birthday": "1982.11.11",
            "first_name": "",
        },
        {
            "phone": 72334567837,
            "last_name": "buy",
            "first_name": "mike",
            "birthday": "1982.11.11",
            "gender": 2,
        },
    ],
)
def test_online_score_ok_data_with_cache(args, server):
    req = {
        "account": "company",
        "login": "test1",
        "method": "online_score",
        "token": "",
        "arguments": args,
    }
    res, status = server.get_response(req)
    assert api.OK == status
    key_parts = [
        args.get("first_name") or "",
        args.get("last_name") or "",
        (str(args.get("phone")) if args.get("phone") is not None else ""),
        (
            datetime.strptime(args.get("birthday"), "%Y.%m.%d").strftime("%Y%m%d")
            if args.get("birthday") is not None
            else ""
        ),
    ]
    key = "uid:" + hashlib.md5("".join(key_parts).encode("utf-8")).hexdigest()
    res_score = None if not isinstance(res, dict) else res.get("score")
    cache_score = server.store.cache_get(key)
    cache_score = float(cache_score) if cache_score is not None else None
    assert cache_score == res_score


@pytest.mark.parametrize(
    "args",
    [
        {"date": "1980.11.12", "client_ids": [2, 3]},
        {"date": "1980.11.13", "client_ids": [1, 2, 3]},
        {"date": "1980.11.14", "client_ids": [3, 4, 5, 6]},
    ],
)
def test_clients_interests_ok_data_with_cache(args, server):
    req = {
        "account": "company",
        "login": "test1",
        "method": "clients_interests",
        "token": "",
        "arguments": args,
    }
    res_generated, status = server.get_response(req)
    assert api.OK == status
    res_from_cache, status = server.get_response(req)
    assert api.OK == status
    assert res_generated == res_from_cache
    assert res_generated == {
        str(cid): server.store.get(f"i:{cid}") for cid in args["client_ids"]
    }
