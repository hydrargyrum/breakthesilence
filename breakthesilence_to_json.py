#!/usr/bin/env python3

from base64 import b64encode, b64decode
from enum import IntFlag
import hmac
import json
from pathlib import Path
import sqlite3
import sys

import Cryptodome.Protocol.KDF
import Cryptodome.Cipher.AES
import Cryptodome.Util.Padding


# From MmsSmsColumns.java
class Types(IntFlag):
    TOTAL_MASK = 0xFFFFFFFF

    # Base Types
    BASE_TYPE_MASK = 0x1F

    BASE_INBOX_TYPE = 20
    BASE_OUTBOX_TYPE = 21
    BASE_SENDING_TYPE = 22
    BASE_SENT_TYPE = 23
    BASE_SENT_FAILED_TYPE = 24
    BASE_DRAFT_TYPE = 27

    # Message attributes
    MESSAGE_ATTRIBUTE_MASK = 0xE0
    MESSAGE_FORCE_SMS_BIT = 0x40

    # Key Exchange Information
    KEY_EXCHANGE_MASK = 0xFF00
    KEY_EXCHANGE_BIT = 0x8000
    KEY_EXCHANGE_STALE_BIT = 0x4000
    KEY_EXCHANGE_PROCESSED_BIT = 0x2000
    KEY_EXCHANGE_CORRUPTED_BIT = 0x1000
    KEY_EXCHANGE_INVALID_VERSION_BIT = 0x800
    KEY_EXCHANGE_BUNDLE_BIT = 0x400
    KEY_EXCHANGE_IDENTITY_UPDATE_BIT = 0x200

    # Secure Message Information
    SECURE_MESSAGE_BIT = 0x800000
    END_SESSION_BIT = 0x400000
    PUSH_MESSAGE_BIT = 0x200000

    # Group Message Information
    GROUP_UPDATE_BIT = 0x10000
    GROUP_QUIT_BIT = 0x20000

    # XMPP Message Information
    XMPP_EXCHANGE_BIT = 0x30000

    # Encrypted Storage Information
    ENCRYPTION_MASK = 0xFF000000
    ENCRYPTION_SYMMETRIC_BIT = 0x80000000
    ENCRYPTION_ASYMMETRIC_BIT = 0x40000000
    ENCRYPTION_REMOTE_BIT = 0x20000000
    ENCRYPTION_REMOTE_FAILED_BIT = 0x10000000
    ENCRYPTION_REMOTE_NO_SESSION_BIT = 0x08000000
    ENCRYPTION_REMOTE_DUPLICATE_BIT = 0x04000000
    ENCRYPTION_REMOTE_LEGACY_BIT = 0x02000000

    errors_mask = (
        KEY_EXCHANGE_STALE_BIT
        | KEY_EXCHANGE_CORRUPTED_BIT
        | KEY_EXCHANGE_INVALID_VERSION_BIT
        | ENCRYPTION_REMOTE_FAILED_BIT
        | ENCRYPTION_REMOTE_NO_SESSION_BIT
        | ENCRYPTION_REMOTE_DUPLICATE_BIT
        | ENCRYPTION_REMOTE_LEGACY_BIT
    )
    control_mask = (
        END_SESSION_BIT
        | GROUP_UPDATE_BIT
        | GROUP_QUIT_BIT
    )


def to_uint(i):
    if i >= 0:
        return i
    return (1 << 32) - abs(i)


class Converter:
    def __init__(self, root, enckey, mackey):
        super().__init__()
        self.root = root
        self.enckey = enckey
        self.mackey = mackey
        self.db = None

    def decrypt(self, data):
        aes_size = 16

        macer = hmac.new(self.mackey, digestmod='sha1')
        iv_and_enc, mac = data[:-macer.digest_size], data[-macer.digest_size:]
        macer.update(iv_and_enc)
        assert hmac.compare_digest(macer.digest(), mac), "hmac don't match"

        iv, enc = iv_and_enc[:aes_size], iv_and_enc[aes_size:]

        cipher = Cryptodome.Cipher.AES.new(self.enckey, Cryptodome.Cipher.AES.MODE_CBC, iv=iv)
        return Cryptodome.Util.Padding.unpad(cipher.decrypt(enc), aes_size)

    def convert(self, outpath):
        self.db = sqlite3.connect(str(self.root / 'databases' / 'messages.db'))

        dmessages = {}
        dparts = {}
        daddrs = {}

        for sms in self.get_rows('select * from sms'):
            # "type" hasn't the same meaning as in android sms database
            sms['flags'] = to_uint(sms['type'])

            sms['type'] = 1
            if sms['flags'] & Types.BASE_OUTBOX_TYPE:
                sms['type'] = 2

            if sms['flags'] & Types.KEY_EXCHANGE_MASK:
                sms['body'] = f"Key exchange (flags = {sms['flags']:#010x}) - {sms['body']}"
            elif sms['flags'] & Types.errors_mask:
                sms['body'] = f"Error (flags = {sms['flags']:#010x}) - {sms['body']}"
            elif sms['flags'] & Types.control_mask:
                sms['body'] = f"Control (flags = {sms['flags']:#010x}) - {sms['body']}"
            else:
                sms['body'] = self.decrypt(b64decode(sms["body"])).decode('utf-8')

            dmessages.setdefault(sms['thread_id'], []).append(sms)

        for part in self.get_rows('select * from part'):
            part_path = self.root / 'app_parts' / Path(part['_data']).name
            bin = self.decrypt(part_path.read_bytes())
            part['my_content'] = b64encode(bin).decode('ascii')
            dparts.setdefault(part['mid'], []).append(part)

        for addr in self.get_rows('select * from mms_addresses'):
            daddrs.setdefault(addr['mms_id'], []).append(addr['address'])

        for mms in self.get_rows('select * from mms'):
            mms['msg_box'] = to_uint(mms['msg_box'])
            if mms['body']:
                mms['body'] = self.decrypt(b64decode(mms["body"])).decode('utf-8')
            mms['parts'] = dparts.get(mms['_id'], [])
            mms['addresses'] = daddrs.get(mms['_id'], [])
            dmessages.setdefault(mms['thread_id'], []).append(mms)

        outdata = {
            'conversations': list(dmessages.values()),
        }

        with open(outpath, 'w') as fd:
            json.dump(outdata, fd)

    def get_rows(self, req):
        cur = self.db.execute(req)
        names = [c[0] for c in cur.description]
        for row in cur:
            yield dict(zip(names, row))


print('Enter output of run-jar.sh:')
props = {}
while True:
    try:
        key, _, value = input().partition('=')
    except EOFError:
        break
    props[key.strip()] = value.strip()

converter = Converter(
    Path(sys.argv[1]),
    b64decode(props['encryption_key']),
    b64decode(props['mac_key']),
)
print('OK, successfully read properties.')

print('Proceeding to conversion, this may take a while, please wait!')
converter.convert(sys.argv[2])
print('Done!')
