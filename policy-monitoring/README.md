IC Policy Monitoring Pipeline
=============================

The script `main.py` performs subsets of the following actions:
* determining which system tests were recently finished
    * unless `-g` is given
* extracting Elasticsearch documents for system tests
    * unless `-r` is given
* save raw Elasticsearch documents into a file
    * only if `raw` is specified among the values of `-m`
* pre-processing raw Elasticsearch logs into an event stream
    * if `universal_policy` is specified among the values of `-m`
* save event stream into a file
    * if `save_logs` is specified among the values of `-m`
* checking the event stream against supported formal policies
    * either all available policies or the subset specified via `-p`
* notifying the end user about policy violations and pipeline crashes

Prerequisites
-------------
1. Git
2. Python 3
3. VPN connection to reach [http://elasticsearch.testnet.dfinity.systems](http://elasticsearch.testnet.dfinity.systems)
4. Access tokens (TODO)

For example, the following should be enough on Ubuntu 22.04 LTS:

```sh
sudo apt install gcc python3.10-venv python3-dev
```

Usage
-----
To use this script, run the following commands: 

1. `$ python3 -m venv venv` 
2. `$ source venv/bin/activate`
3. `(venv) $ pip install wheel`
4. `(venv) $ pip install -r ./requirements.txt`
5. `(venv) $ python main.py --install_monpoly_docker_image`
6. `(venv) $ python main.py -g [Farm group id] -p [policy name(s)]`
7. To list all available policies, run `(venv) $ python main.py --list_policies`
8. To list all available options, run `(venv) $ python main.py --help` 

Testing
-------

Run Monpoly IO tests with the following command:
```sh
(venv) $ python -m tests.monpoly_io
```

Run MFOTL policy tests with the following command:
```sh
python -m tests.mfotl_sanity_tests
```
