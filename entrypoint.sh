#!/bin/sh
set -e
while getopts "hc:p:l:" o; do
    case "${o}" in
        h)
            echo "-c <custom rules path (optional)> -p <path to scan> -l <level (optional)>"
            exit 0
        ;;
        c)
            export customRules=${OPTARG}
        ;;
        p)
            export path=${OPTARG}
        ;;
        l)
            export level=${OPTARG}
        ;;
    esac
done
ARGS=""
if [ $customRules ]; then
    customRulesArg="--custom-rules $customRules"
    ARGS="$ARGS $customRulesArg"
fi

if [ $level ]; then
    levelArg="--severity-level $level"
    ARGS="$ARGS $levelArg"
fi


python3 -m ludvig fs scan --path ${path} ${ARGS} -otable