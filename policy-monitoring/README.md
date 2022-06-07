IC Policy Monitoring Pipeline
=============================

The script `main.py` performs subsets of the following actions:
* 🔭 determining which system tests were recently finished
    * _unless `-g` is given, fixing a Farm group name_
* ⬇️ extracting Elasticsearch documents for system tests
    * _unless `-r` is given, specifying a file with previously downloaded raw
      logs_
* 📁 save raw Elasticsearch documents into a file
    * _if `raw` is specified among the values of `-m`_
* ⚙️ pre-processing raw Elasticsearch logs into an event stream
    * _if `universal_policy` or `save_event_stream` are specified among the
      values of `-m`_
* 📁 save event stream into a file
    * _if `save_event_stream` is specified among the values of `-m`_
* 🔎 checking the event stream against supported formal policies
    * _either all available policies or the subset specified via `-p`_
* 📨 notifying the end user about policy violations and pipeline crashes
    * _via Slack_

Prerequisites
-------------
1. Git
2. Python 3
3. VPN connection to reach
   [http://elasticsearch.testnet.dfinity.systems](http://elasticsearch.testnet.dfinity.systems)
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
6. `(venv) $ python main.py -g [Farm group name] -p [policy name(s)]`
    - _Note: use option `-l` to specify the maximal number of log entries that
      will be pre-processed. The default value `1000` safeguards from accidental
      command invocations but is almost certainly insufficient for monitoring
      policies in system tests. To download _all the logs_ associated with the
      given `Farm group name`, set `-l 0`; this may result in transmitting
      gigabytes of logs._
7. To list all available policies, run `(venv) $ python main.py --list_policies`
8. To list all available options, run `(venv) $ python main.py --help` 


🐧 Remark. On Linux, prefix `python main.py` with `sudo -E env PATH=$PATH`
   unless you pass the flag `--without_docker`.

Testing
-------

Run Monpoly IO tests with the following command:
```sh
(venv) $ python -m tests.monpoly_io
```

Run MFOTL policy tests with the following command:
```sh
(venv) python -m tests.mfotl_sanity
```
