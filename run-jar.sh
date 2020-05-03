#!/bin/sh -e

cd "$(dirname "$0")"

if [ -z "$BCPROV_JAR" ]
then
	BCPROV_JAR=$(ls bcprov*.jar | sed 1q)
fi

if [ -z "$BCPROV_JAR" ]
then
	cat << EOF >&2
Missing bcprov.jar.
Set BCPROV_JAR environment variable to point to JAR path.

Or download it in current directory, for example with:
	curl -LO https://bouncycastle.org/download/bcprov-jdk15on-165.jar
EOF
	exit 1
fi

if [ $# -ne 1 ]
then
	echo "usage: $0 SILENCE_EXPORT_DIR_PATH" >&2
	exit 64
fi

old_tty=$(stty -g)
trap "stty $old_tty" EXIT

stty -echo
printf "Password (leave empty if empty): " >&2
read passwd
echo >&2

echo "$passwd" | java -cp "$BCPROV_JAR:build/breakthesilence.jar" re.indigo.breakthesilence.MasterSecretUtil "$@"
