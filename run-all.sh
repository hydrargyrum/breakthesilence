#!/bin/sh -e

cd "$(dirname "$0")"

if [ $# -ne 2 ]
then
	echo "usage: $0 SILENCEEXPORT_DIR_PATH OUTPUT_FILE" >&2
	exit 64
fi


# Use a temp file to pipe jar output to python input.
# Why? Else the python command starts printing its help, which is mixed with
# the jar program help. Let's sequence them instead.
props=$(mktemp silence-props.XXXXXX)
trap "rm $props" EXIT

./run-jar.sh "$1" > "$props"
./breakthesilence_to_json.py "$1" "$2" < "$props"
