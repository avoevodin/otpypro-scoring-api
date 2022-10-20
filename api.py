#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = HTTPStatus.OK
BAD_REQUEST = HTTPStatus.BAD_REQUEST
FORBIDDEN = HTTPStatus.FORBIDDEN
NOT_FOUND = HTTPStatus.NOT_FOUND
INVALID_REQUEST = HTTPStatus.UNPROCESSABLE_ENTITY
INTERNAL_ERROR = HTTPStatus.INTERNAL_SERVER_ERROR
ERRORS = [BAD_REQUEST, FORBIDDEN, NOT_FOUND, INVALID_REQUEST, INTERNAL_ERROR]
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

NULL_VALUES = ["", None, {}, (), []]


class BaseField(abc.ABC):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __str__(self):
        return type(self).__name__

    def __repr__(self):
        return str(type(self))

    @abc.abstractmethod
    def validate(self, value):
        if self.required and value is None:
            raise ValueError(f"Field {self} is required")
        if not self.nullable and value in NULL_VALUES:
            raise ValueError(f"Field {self} is not nullable")


class CharField(BaseField):
    def validate(self, value):
        super().validate(value)


class ArgumentsField(BaseField):
    def validate(self, value):
        super().validate(value)


class EmailField(BaseField):
    def validate(self, value):
        super().validate(value)


class PhoneField(BaseField):
    def validate(self, value):
        super().validate(value)


class DateField(BaseField):
    def validate(self, value):
        super().validate(value)


class BirthDayField(BaseField):
    def validate(self, value):
        super().validate(value)


class GenderField(BaseField):
    def validate(self, value):
        super().validate(value)


class ClientIDsField(BaseField):
    def validate(self, value):
        super().validate(value)


class RequestMeta(type):
    def __new__(mcs, name, bases, dct):
        modified_dct = dct.copy()
        modified_dct["_fields"] = {}
        for k, v in dct.items():
            if isinstance(v, BaseField):
                modified_dct["_fields"][k] = v
                del modified_dct[k]
        return super().__new__(mcs, name, bases, modified_dct)


class BaseRequest(metaclass=RequestMeta):
    def __init__(self, body, method):
        self.body = body
        self.method = method
        self._errors = {}

    def __str__(self):
        return self.method

    def validate(self):
        self._errors = {}
        for k, v in self._fields.items():
            if k not in self.body and not v.required:
                continue

            value = self.body.get(k)
            try:
                v.validate(value)
                setattr(self, k, value)
            except ValueError as e:
                self._errors[k] = str(e)

    @property
    def errors(self):
        return self._errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        super().validate()
        valid_pairs = [
            ("phone", "email"),
            ("first_name", "last_name"),
            ("gender", "birthday"),
        ]
        if not self.errors.get("arguments"):
            for pair in valid_pairs:
                if (
                    getattr(self, pair[0], None) not in NULL_VALUES
                    and getattr(self, pair[1], None) not in NULL_VALUES
                ):
                    return
            self.errors["arguments"] = (
                f"Arguments for the method '{self}' must contain "
                f"at least one valid pair: {valid_pairs}"
            )

    def get_response(self):
        pass


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        str_to_hash = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        str_to_hash = request.account + request.login + SALT
    digest = hashlib.sha512(str_to_hash.encode("utf-8")).hexdigest()
    print(digest)
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, OK
    method_req = MethodRequest(request["body"], "method")
    method_req.validate()
    if method_req.errors:
        return method_req.errors, INVALID_REQUEST
    if not check_auth(method_req):
        return f"Login failed for user {method_req.login}", FORBIDDEN

    allowed_ops = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest,
    }

    if method_req.method not in allowed_ops:
        return f"Method {method_req.method!r} is not found", NOT_FOUND

    req = allowed_ops[method_req.method](method_req.arguments, method_req.method)
    req.validate()
    if req.errors:
        return req.errors, INVALID_REQUEST
    res = req.get_response()
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = str(
                self.rfile.read(int(self.headers["Content-Length"])),
                encoding="utf-8",
            )
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": int(code)}
        else:
            r = {"error": response or code.phrase, "code": int(code)}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(
        filename=opts.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
