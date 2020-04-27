from enum import Enum
import sigrokdecode as srd

import json
import pyvesc
from pyvesc.messages.getters import *
from pyvesc.messages.setters import *

class No_more_data(Exception):
    pass

class Data:
    def __init__(self, start, end, data):
        self.start = start
        self.end = end
        self.data = data

class PacketDecoder:
    class State(Enum):
        idle = 'Idle'
        header = 'Header'
        payload = 'Payload'

    state = State.idle
    total_length = 0
    prefix = None

    def __init__(self, parent, start):
        self.data = []
        self.parent = parent
        self.start = start
        self.last_read = start
        self.last_byte_put = -1
        self.minimum_length = 6
        self.start_new_frame = False
        self.has_error = False

    def add_data(self, start, end, data):
        ptype, rxtx, pdata = data
        self.last_read = end
        if ptype == 'FRAME' and pdata[1]:
            #print("data {} {} {}".format(start, end, data))
            self.data.append(Data(start, end, pdata[0]))
            self.parse()

    def puti(self, byte_to_put, annotation, message):
        #print("puti {}-{} {} {}".format(
        #            self.last_byte_put + 1,
        #            byte_to_put,
        #            self.prefix + annotation,
        #            message))

        if byte_to_put > len(self.data) - 1:
            return

        if annotation == 'error':
            self.has_error = True

        if byte_to_put > self.last_byte_put:
            self.parent.puta(
                    self.data[self.last_byte_put + 1].start,
                    self.data[byte_to_put].end,
                    self.prefix + '_' + annotation,
                    message)
            self.last_byte_put = byte_to_put

    def putl(self, annotation, message, maximum = None):
        last_byte_address = len(self.data) - 1
        if maximum is not None and last_byte_address > maximum:
            return
        self.puti(last_byte_address, annotation,
                message.format(self.data[-1].data))

    def close(self, message_overflow):
        data = self.data
        if len(data) < self.minimum_length:
            if len(data) == 0:
                return
            self.parent.puta(
                    data[self.last_byte_put].end, message_overflow,
                    self.prefix + '_error',
                    'Message too short or not finished')
            self.has_error = True

        if len(data) > 256:
            try:
                self.puti(len(data) - 1, 'error',
                        'Frame is longer than 256 bytes')
            except No_more_data:
                pass

    def parse(self):
        data = self.data

        if len(data) == 1:
            self.puti(0, 'start', 'Start')

        if len(data) == 2:
            packet_type = data[0].data
            payload_len = data[1].data
            if packet_type == 2:
                self.total_length = payload_len + 5
            else:
                # Not supported
                pass

            self.puti(1, 'length', 'Len: {}'.format(payload_len))

        if len(data) == self.total_length:
            self.start_new_frame = True
            msg = self.parse_message()
            crc = (data[-3].data << 8) | data[-2].data
            self.puti(len(data) - 2, 'crc', 'CRC: 0x%x'%(crc))
            self.puti(len(data) - 1, 'stop', 'Stop')

            self.parent.puta(
                    data[0].start,
                    data[-1].end,
                    self.prefix + '_packet',
                    msg)
            #self.putl('error', 'Frame too long')

    def parse_vesc(self):
        buf = bytes([x.data for x in self.data])
        vmsg, consumed = pyvesc.decode(buf)
        if not vmsg:
            return None

        if self.parent.options['json']:
            fields = {}
            for f in vmsg.fields:
                name = f[0]
                value = vmsg.__getattribute__(name)
                if type(value) == bytes:
                    value = value.decode()
                fields[name] = value

            msg = json.dumps({
                'command': type(vmsg).__name__,
                'direction': self.prefix,
                'fields': fields
                })
        else:
            arg = ', '.join([f[0] + "=" + str(vmsg.__getattribute__(f[0])) for f in vmsg.fields])
            msg = '{} {}'.format(type(vmsg).__name__, arg)
        self.puti(len(self.data) - 4, 'command', msg)
        return msg


class RxPacketDecoder(PacketDecoder):
    prefix = "rx"

    def parse_message(self):
        data = self.data
        cmd = data[2].data
        try:
            msg = self.parse_vesc()
        except Exception as e:
            print(e)
            msg = 'Command: {}'.format(cmd)
            self.puti(2, 'command', msg)
            self.puti(len(data) - 4, 'payload', '')

        return msg


class TxPacketDecoder(PacketDecoder):
    prefix = "tx"

    def parse_message(self):
        data = self.data
        cmd = data[2].data
        if cmd == GetValues.id:
            msg = 'Get Values'
            self.puti(2, 'command', msg)
        else:
            try:
                msg = self.parse_vesc()
            except Exception as e:
                #print(e)
                msg = 'Command: {}'.format(cmd)
                self.puti(2, 'command', msg)
                self.puti(len(data) - 4, 'payload', '')
        
        return msg

class Decoder(srd.Decoder):
    api_version = 3
    id = 'vesc'
    name = 'VESC'
    longname = 'VESC protocol'
    desc = 'VESC motor control serial protocol'
    license = 'gplv2+'
    inputs = ['uart']
    outputs = []
    optional_channels = ()
    annotations = (
        ('rx_packet', ''),
        ('tx_packet', ''),
        ('rx_start', ''),
        ('tx_start', ''),
        ('rx_length', ''),
        ('tx_length', ''),
        ('rx_payload', ''),
        ('tx_payload', ''),
        ('rx_crc', ''),
        ('tx_crc', ''),
        ('rx_stop', ''),
        ('tx_stop', ''),
        ('rx_command', ''),
        ('tx_command', ''),
        ('rx_error', ''),
        ('tx_error', ''),
    )
    annotation_rows = (
        ('rx', 'RX message', (0,)),
        ('rx_msg', 'RX details', (2,4,6,8,10,12,14)),
        ('tx', 'TX message', (1,)),
        ('tx_msg', 'TX details', (3,5,7,9,11,13,15)),
    )
    options = (
        {'id': 'json', 'desc': 'JSON output', 'default': False},
    )
    bitlength = None

    def __init__(self, **kwargs):
        self.reset()

    def reset(self):
        self.decoder_tx = None
        self.decoder_rx = None

    def metadata(self, key, value):
        pass

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def puta(self, start, end, ann_str, message):
        ann = [s[0] for s in self.annotations].index(ann_str)
        self.put(start, end, self.out_ann, [ann, [message]])

    def decode(self, ss, es, data):
        ptype, rxtx, pdata = data
        if ptype not in ('FRAME', 'STARTBIT', 'STOPBIT'):
            return

        if self.bitlength is None:
            if ptype == 'STARTBIT' or ptype == 'STOPBIT':
                self.bitlength = es - ss
            else:
                return

        if rxtx == 0:
            if (self.decoder_rx is None) or self.decoder_rx.start_new_frame:
                self.decoder_rx = RxPacketDecoder(self, ss)
            decoder = self.decoder_rx
        if rxtx == 1:
            if (self.decoder_tx is None) or self.decoder_tx.start_new_frame:
                self.decoder_tx = TxPacketDecoder(self, ss)
            decoder = self.decoder_tx

        if (ss - decoder.last_read) <= self.bitlength * 10:
            decoder.add_data(ss, es, data)
        else:
            if len(decoder.data) > 0:
                decoder.close(decoder.data[-1].end + self.bitlength * 3)
            decoder.start_new_frame = True
            self.decode(ss, es, data)
