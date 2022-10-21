# Scoring API homework

#### Scoring API homework for OTUS Python Pro course


### Running:
* Run server. Port and log file path aren't required
```shell
python3 -m api -p <port> -l <path_to_log_file>
```
#### Request params:
* account - company name
* login - user login
* method - method name (online_score/clients_interests)
* token - access token
* arguments - dict of method args
#### Request Online Score method example:
* Method arguments:
  * phone
  * email
  * first_name
  * last_name
  * birthday
  * gender
* Example:
```shell
python3 -m api -p 8888
curl -X POST -H "Content-Type:application/json" -d '{"account":"company","login":"test","method":"online_score","token":"d3c53f4116f8d0b05a56acff0910b68ff3c3ad990a995c98e4a0f9c6eacfbbb42eb5fe0b9bc1580be27a0cfa8cbd4cbeabd9c5e4cc3ddd362eb0a820bd555ff3","arguments":{"phone":72334567837,"last_name":"buy","first_name":"jack","birthday":"11.11.1952","gender":1}}' http://127.0.0.1:8888/method/
```

#### Request Clients Interests method example:
* Method arguments:
  * client_ids
  * date
* Example:
```shell
python3 -m api -p 8888
curl -X POST -H "Content-Type:application/json" -d '{"account":"company","login":"test","method":"clients_interests","token":"d3c53f4116f8d0b05a56acff0910b68ff3c3ad990a995c98e4a0f9c6eacfbbb42eb5fe0b9bc1580be27a0cfa8cbd4cbeabd9c5e4cc3ddd362eb0a820bd555ff3","arguments":{"date":"11.11.1952","client_ids":[1,2,3]}}' http://127.0.0.1:8888/method/
```

### Tests:

* Running tests:
```shell
python3 -m test
```