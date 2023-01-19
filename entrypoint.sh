#!/bin/bash
set -e
while getopts "hc:p:" o; do
    case "${o}" in
        h)
            echo "-c <custom rules path (optional)> -p <path to scan>"
            exit 0
        ;;
        c)
            export customRules=${OPTARG}
        ;;
        p)
            export path=${OPTARG}
        ;;
    esac
done

if [ $customRules ]; then
    customRulesArg="--custom-rules $customRules"
fi


python3 -m ludvig ${customRulesArg} fs ${path}