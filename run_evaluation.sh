#!/bin/bash
if [ $# -ne 1 ]
  then
    echo "Usage: ./run_evaluation.sh <csvOutputFolder>"
    echo "Runs the evalution used in the paper"
    exit 1
fi
GRADLE_OPTS="-Xms1024m -Xmx4096m" ./gradlew :cli_demo_local:run --args="-o $1 -i 25";
