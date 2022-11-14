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
from scoring import get_score, get_interests
from store import Store

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

VALID_PAIRS = [
    ("phone", "email"),
    ("first_name", "last_name"),
    ("gender", "birthday"),
]

MAX_AGE = 70
PHONE_DIGITS_CNT = 11
PHONE_CODE = "7"


class BaseField(abc.ABC):
    def __init__(self, required=False, nullable=False):
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

        if value not in NULL_VALUES and not isinstance(value, str):
            raise ValueError(f"{self} must be a str")


class ArgumentsField(BaseField):
    def validate(self, value):
        super().validate(value)

        if value not in NULL_VALUES and not isinstance(value, dict):
            raise ValueError(f"{self} must be a dict")


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)

        if "@" not in value:
            raise ValueError(f"{self} must contain '@'")


class PhoneField(BaseField):
    def validate(self, value):
        super().validate(value)

        if value not in NULL_VALUES and not (
            isinstance(value, str) or isinstance(value, int)
        ):
            raise ValueError(f"{self} must be a str or int")

        if isinstance(value, str):
            try:
                int(value)
            except ValueError:
                raise ValueError(f"{self} str must contain only numbers")
        else:
            value = str(value)

        if len(value) != PHONE_DIGITS_CNT:
            raise ValueError(f"{self} must have length {PHONE_DIGITS_CNT}")

        if not value.startswith(PHONE_CODE):
            raise ValueError(f"{self} must start with {PHONE_CODE}")

        return value


class DateField(CharField):
    def validate(self, value):
        super().validate(value)
        if not value:
            return

        try:
            return datetime.datetime.strptime(value, "%Y.%m.%d").date()
        except ValueError:
            raise ValueError(f"{self} must be a 'YYYY.MM.DD' date")


class BirthDayField(DateField):
    def validate(self, value):
        parsed_date = super().validate(value)
        date_today = datetime.date.today()

        if parsed_date and parsed_date < datetime.date(
            year=date_today.year - MAX_AGE,
            month=date_today.month,
            day=date_today.day,
        ):
            raise ValueError(f"{self} must be greater than {MAX_AGE} years ago")
        return parsed_date


class GenderField(BaseField):
    def validate(self, value):
        super().validate(value)

        if value not in GENDERS.keys():
            raise ValueError(
                f"{self} must be one of ({', '.join([str(k) for k in GENDERS.keys()])})"
            )


class ClientIDsField(BaseField):
    def validate(self, value):
        super().validate(value)

        if not isinstance(value, list):
            raise ValueError(f"{self} must be a list")

        if value and not all([isinstance(cid, int) for cid in value]):
            raise ValueError(f"{self} must be a list of int")


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
                value = v.validate(value) or value
                setattr(self, k, value)
            except ValueError as e:
                self._errors[k] = str(e)

    @property
    def errors(self):
        return self._errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def get_response(self, ctx, store, *args, **kwargs):
        client_ids = getattr(self, "client_ids", [])
        ctx["nclients"] = len(client_ids)
        return {str(cid): get_interests(store, cid) for cid in client_ids}


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        super().validate()
        if not self.errors.get("arguments"):
            for pair in VALID_PAIRS:
                if (
                    getattr(self, pair[0], None) not in NULL_VALUES
                    and getattr(self, pair[1], None) not in NULL_VALUES
                ):
                    return
            self.errors["arguments"] = (
                f"Arguments for the method '{self}' must contain "
                f"at least one valid pair: {VALID_PAIRS}"
            )

    def get_response(self, ctx, store, is_admin):
        score_args = {k: getattr(self, k, None) for k in self._fields.keys()}
        ctx["has"] = [k for k, v in score_args.items() if v not in NULL_VALUES]
        return {"score": 42 if is_admin else get_score(store, **score_args)}


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
        str_to_hash = str(request.account) + str(request.login) + SALT
    digest = hashlib.sha512(str_to_hash.encode("utf-8")).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
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
    res = req.get_response(ctx, store, method_req.is_admin)
    return res, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = Store()

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
