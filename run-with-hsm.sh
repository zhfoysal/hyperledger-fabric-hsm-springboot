#!/bin/bash

# Set SoftHSM2 configuration
export SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf

# Run the application
cd /home/xack/Desktop/fabric-blockchain-sample
./gradlew bootRun

