# BreakTheSilence

TL;DR: BreakTheSilence is a tool to decrypt [Silence Android](https://f-droid.org/app/org.smssecure.smssecure) app messages

## Longer version

[Silence](https://silence.im/) is an [open-source](https://f-droid.org/app/org.smssecure.smssecure) Android SMS/MMS app which can encrypt
messages to your recipients.

It also encrypts messages on the phone (even messages that were unencrypted on the wire), unlike other SMS/MMS apps, which helps your privacy if your phone gets lost.
However, it prevents from backuping its messages with [ordinary apps](https://f-droid.org/packages/re.indigo.epistolaire).

Silence itself has 2 backup options:
- export SMSes in a cleartext XML file, but MMSes are not backed up, so it's useless
- export SMSes and MMSes messages in a SQLite database, but messages content is encrypted

BreakTheSilence is a tool that will decrypt messages from the backup SQLite database, and export all messages into JSON.
The JSON format is similar to the one used by our sister project: [Epistolaire](https://gitlab.com/hydrargyrum/epistolaire).

# Technology choice

Silence encryption is [undocumented](https://git.silence.dev/Silence/Silence-Android/-/issues/783) and not really maintained.
After efforts trying to reverse-engineer its source code, I could not determine what key derivation function is used and so could not reimplement decryption in Python. (Mysterious `PBEWITHSHA1AND128BITAES-CBC-BC`)

I eventually gave up and simply used Silence's code (Java) as a blackbox to find the master encryption key.

When the master encryption key is found, another tool can process the SQLite database to decrypt its content, in Python.

# How to use
## Export encrypted database from app
In the Silence app, open the "3 dots" menu, select "Import/Export" and choose "Export encrypted backup".
You will now have a `SilenceExport` directory in `/storage/emulated/0` (user's accessible root dir).

## Transfer the `SilenceExport` to computer
Use whatever means you can: [Syncthing](https://f-droid.org/packages/com.nutomic.syncthingandroid), etc.

## Build BreakTheSilence
TODO convert to `.properties`

Run:
	./build-jar.sh

## Decrypt `SilenceExport` backup dir into a single JSON file
Run:

	./run-all.sh path/to/SilenceExport/ silence-backup.json

`run-all.sh` takes the path to `SilenceExport` dir which contains the exported backup from Silence, and the path to output JSON file.

## Process JSON
You can convert the messages JSON file to many formats with sister project [Epistolaire converters](https://gitlab.com/hydrargyrum/epistolaire/-/tree/master/converters).

The JSON format is easy to use, so one can write another converter.
