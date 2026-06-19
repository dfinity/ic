#!/bin/bash

# This script dynamically starts "guestos@" services to create the right number of VMs per node type

source /opt/ic/bin/config.sh

node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

if [[ $node_reward_type =~ ^type4.1$ ]]; then
    systemctl start guestos@0.service guestos@1.service guestos@2.service guestos@3.service guestos@4.service guestos@5.service guestos@6.service guestos@7.service guestos@8.service guestos@9.service guestos@10.service guestos@11.service guestos@12.service guestos@13.service guestos@14.service guestos@15.service guestos@16.service guestos@17.service guestos@18.service guestos@19.service guestos@20.service guestos@21.service guestos@22.service guestos@23.service guestos@24.service guestos@25.service guestos@26.service guestos@27.service guestos@28.service guestos@29.service guestos@30.service guestos@31.service
elif [[ $node_reward_type =~ ^type4.2$ ]]; then
    systemctl start guestos@0.service guestos@1.service guestos@2.service guestos@3.service guestos@4.service guestos@5.service guestos@6.service guestos@7.service
elif [[ $node_reward_type =~ ^type4.3$ ]]; then
    systemctl start guestos@0.service guestos@1.service guestos@2.service guestos@3.service
elif [[ $node_reward_type =~ ^type4.4$ ]]; then
    systemctl start guestos@0.service guestos@1.service
fi
