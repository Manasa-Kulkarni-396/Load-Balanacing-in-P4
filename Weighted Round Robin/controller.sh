#!/bin/bash

CLI_PATH=/usr/local/bin/simple_switch_CLI

echo "table_modify ecmp_nhop set_ecmp_nhop  0 00:00:00:00:03:03 10.0.3.3 3" | $CLI_PATH --thrift-port 9090
echo "table_modify ecmp_nhop set_ecmp_nhop  1 00:00:00:00:03:03 10.0.3.3 3" | $CLI_PATH --thrift-port 9090
echo "table_modify ecmp_nhop set_ecmp_nhop  2 00:00:00:00:03:03 10.0.3.3 3" | $CLI_PATH --thrift-port 9090
echo "table_dump ecmp_nhop" |  $CLI_PATH --thrift-port 9090
