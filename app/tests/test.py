import unittest
from functools import wraps

from app import api
from app.store import Store


def cases(cases_list):
    def decorator(func):
        @wraps(func)
        def wrapper(*args):
            for case in cases_list:
                new_args = args + (case if isinstance(case, tuple) else (case,))
                func(*new_args)

        return wrapper

    return decorator


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.store = Store()

    def get_response(self, request):
        return api.method_handler(
            {"body": request, "headers": self.headers}, self.context, self.store
        )

    @staticmethod
    def set_valid_auth(request):
        method_request = api.MethodRequest(request, "method")
        method_request.validate()
        if method_request.errors:
            return method_request.errors, api.INVALID_REQUEST
        request["token"] = api.generate_token(method_request)

    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases(
        [
            {
                "account": "horns&hoofs",
                "login": "h&f",
                "method": "online_score",
                "token": "",
                "arguments": {},
            },
            {
                "account": "horns&hoofs",
                "login": "h&f",
                "method": "online_score",
                "token": "sdd",
                "arguments": {},
            },
            {
                "account": "horns&hoofs",
                "login": "admin",
                "method": "online_score",
                "token": "",
                "arguments": {},
            },
        ]
    )
    def test_invalid_auth(self, request):
        _, status = self.get_response(request)
        self.assertEqual(api.FORBIDDEN, status)

    @cases(
        [
            {
                "account": "company",
                "login": "test",
                "method": "online_score",
                "token": "",
                "arguments": {
                    "phone": 72334567837,
                    "last_name": "buy",
                    "first_name": "mike",
                    "birthday": "1982.11.11",
                    "gender": 2,
                },
            },
            {
                "account": "",
                "login": "test2",
                "method": "online_score",
                "token": "",
                "arguments": {
                    "phone": 72334567837,
                    "birthday": "1982.11.11",
                    "gender": 2,
                },
            },
        ]
    )
    def test_valid_auth(self, request):
        self.set_valid_auth(request)
        _, status = self.get_response(request)
        self.assertEqual(api.OK, status)

    @cases(
        [
            {
                "account": "company",
                "login": "test",
                "method": "clients_interests",
                "token": "",
                "arguments": {"arg": "val"},
            },
            {
                "account": "company",
                "login": "test1",
                "method": "online_score",
                "token": "",
                "arguments": {},
            },
            {
                "account": "",
                "login": "test2",
                "method": "online_score",
                "token": "",
            },
            {
                "account": "",
                "login": "test2",
                "method": "online_score",
                "token": "",
                "arguments": [1, 2],
            },
            {
                "account": "company",
                "login": "test",
                "method": "",
                "token": "",
                "arguments": {},
            },
        ]
    )
    def test_invalid_method_request(self, request):
        self.set_valid_auth(request)
        res, status = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, status)
        self.assertTrue(len(res))

    @cases(
        [
            {
                "account": "company",
                "login": "test",
                "method": "bar",
                "token": "",
                "arguments": {},
            },
            {
                "account": "",
                "login": "test2",
                "method": "foo",
                "token": "",
                "arguments": {},
            },
        ]
    )
    def test_not_found_method_request(self, request):
        self.set_valid_auth(request)
        res, status = self.get_response(request)
        self.assertEqual(api.NOT_FOUND, status)
        self.assertTrue(len(res))

    @cases(
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
        ]
    )
    def test_online_score_ok_req(self, arguments):
        request = {
            "account": "company",
            "login": "test1",
            "method": "online_score",
            "token": "",
            "arguments": arguments,
        }
        self.set_valid_auth(request)
        res, status = self.get_response(request)
        self.assertEqual(api.OK, status)
        self.assertTrue(len(res))
        self.assertTrue(
            all(
                k in self.context["has"]
                for k, v in arguments.items()
                if v not in api.NULL_VALUES
            )
        )

    @cases(
        [
            {
                "phone": 72334567837,
                "email": "email.com",
            },
            {
                "first_name": "Mike",
                "last_name": "",
            },
            {
                "gender": "1",
                "birthday": "1982.11.11",
            },
            {
                "phone": "92334567837",
                "last_name": "buy",
                "first_name": "mike",
                "birthday": "1982.11.11",
                "gender": 2,
            },
            {
                "phone": "79111111111",
                "email": "1",
                "last_name": "buy",
                "first_name": "mike",
                "birthday": "1982.11.11",
                "gender": 2,
            },
            {
                "phone": {},
                "email": "1@1.com",
                "last_name": "buy",
                "first_name": "mike",
                "birthday": "1982.11.11",
                "gender": 2,
            },
            {
                "phone": "79111111111",
                "last_name": [1, 2],
                "first_name": "mike",
                "birthday": "1982.11.11",
                "gender": 2,
            },
            {
                "phone": [2, 3],
                "last_name": "smith",
                "first_name": "mike",
                "birthday": "1982.11.11",
                "gender": 2,
            },
            {
                "phone": "7921f223344",
                "last_name": "smith",
                "first_name": "mike",
                "birthday": "1982.11.11",
                "gender": 2,
            },
            {
                "phone": "7921f223344",
                "last_name": "smith",
                "first_name": "mike",
                "birthday": "11.11.1982",
                "gender": 2,
            },
            {
                "phone": "7921f223344",
                "last_name": "smith",
                "first_name": "mike",
                "birthday": "1952.11.11",
                "gender": 2,
            },
            {
                "phone": "7921f223344",
                "last_name": "smith",
                "first_name": "mike",
                "birthday": "",
                "gender": 0,
            },
        ]
    )
    def test_online_score_fail_req(self, arguments):
        request = {
            "account": "company",
            "login": "test1",
            "method": "online_score",
            "token": "",
            "arguments": arguments,
        }
        self.set_valid_auth(request)
        res, status = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, status)
        self.assertTrue(len(res))

    @cases(
        [
            {"date": "1980.11.11", "client_ids": [1, 2, 3]},
            {"date": "1980.11.11", "client_ids": [2, 3]},
            {"date": "1980.11.11", "client_ids": [23, 34]},
        ]
    )
    def test_clients_interests_ok_req_without_cache(self, arguments):
        request = {
            "account": "company",
            "login": "test1",
            "method": "clients_interests",
            "token": "",
            "arguments": arguments,
        }
        self.set_valid_auth(request)
        with self.assertRaises(ConnectionRefusedError):
            self.get_response(request)

    @cases(
        [
            {"date": "1980.11.12", "client_ids": []},
            {"date": "1980.11.12", "client_ids": "error"},
            {"date": "23", "client_ids": [2, 3]},
        ]
    )
    def test_clients_interests_fail_req_without_cache(self, arguments):
        request = {
            "account": "company",
            "login": "test1",
            "method": "clients_interests",
            "token": "",
            "arguments": arguments,
        }
        self.set_valid_auth(request)
        res, status = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, status)
        self.assertTrue(len(res))


if __name__ == "__main__":
    unittest.main()
