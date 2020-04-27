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

# remove dir before?
mkdir -p build
javac -cp "$BCPROV_JAR" -d build $(find src -name "*.java")
cd build
jar cfve breakthesilence.jar re.indigo.breakthesilence.MasterSecretUtil *

echo Successful build in build/breakthesilence.jar
