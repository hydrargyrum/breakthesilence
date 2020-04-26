#!/usr/bin/env python3

from base64 import b64encode, b64decode
from enum import IntEnum
import hmac
import json
from pathlib import Path
import sqlite3
import sys

import Cryptodome.Protocol.KDF
import Cryptodome.Cipher.AES
import Cryptodome.Util.Padding


class MessageFlags(IntEnum):
    key_exchange_mask = 0xFF00
    outgoing = 0x15
    errors_mask = 0x1B000000


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
        self.db = sqlite3.connect(self.root / 'databases' / 'messages.db')

        dmessages = {}
        dparts = {}
        daddrs = {}

        for sms in self.get_rows('select * from sms'):
            # "type" hasn't the same meaning as in android sms database
            sms['flags'] = to_uint(sms['type'])

            sms['type'] = 1
            if sms['flags'] & MessageFlags.outgoing:
                sms['type'] = 2

            if sms['flags'] & MessageFlags.key_exchange_mask:
                sms['body'] = f"Key exchange (flags = {sms['flags']:#010x}) - {sms['body']}"
            elif sms['flags'] & MessageFlags.errors_mask:
                sms['body'] = f"Error (flags = {sms['flags']:#010x}) - {sms['body']}"
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

        with open(sys.argv[2], 'w') as fd:
            json.dump(outdata, fd)

    def get_rows(self, req):
        cur = self.db.execute(req)
        names = [c[0] for c in cur.description]
        for row in cur:
            yield dict(zip(names, row))


Converter(
    Path(sys.argv[1]),
    b'',
    b'',
).convert(sys.argv[2])
