# YMSG protocol implementation

from twisted.internet import reactor, defer, protocol
from twisted.python import log
import urllib2
import hashlib
import base64
import struct
import time

YAHOO_PAGER_HOST = "scsa.msg.yahoo.com"
YAHOO_PAGER_PORT = 5050

YAHOO_TOKEN_URL = "https://login.yahoo.com/config/pwtoken_get?src=ymsgr" \
                            "&ts=&login=%s&passwd=%s&chal=%s"
YAHOO_LOGIN_URL = "https://login.yahoo.com/config/pwtoken_login?src=ymsgr" \
                            "&ts=&token=%s"

YAHOO_PAIR_MARKER       = "\xc0\x80"

YAHOO_SERVICE_LOGON     = 0x01
YAHOO_SERVICE_LOGOFF    = 0x02
YAHOO_SERVICE_MESSAGE   = 0x06
YAHOO_SERVICE_PING      = 0x12
YAHOO_SERVICE_NOTIFY    = 0x4B
YAHOO_SERVICE_HANDSHAKE = 0x4C
YAHOO_SERVICE_AUTHRESP  = 0x54
YAHOO_SERVICE_AUTHLIST  = 0x55
YAHOO_SERVICE_AUTH      = 0x57
YAHOO_SERVICE_BUDDYAUTH = 0xD6
YAHOO_SERVICE_BUDDYLIST = 0xF0

#YAHOO_STATUS_TYPING     = 0x16

class YmsgConnection(protocol.Protocol):
    def __init__(self, username, password):
        self.username = username.lower()
        self.password = password
        self.sessionid = 0
        self.buffer = ''

    def webLogin(self, challenge):
        url = YAHOO_TOKEN_URL % (self.username, self.password, 'OK')
        try:
            data = urllib2.urlopen(url).read().split('\r\n')
        except Exception, e:
            self.error('webLogin error: %s' % e)
            return

        if data[0] != '0':
            self.error(data[0])
            return False
        token = data[1].split('=')[1]

        url = YAHOO_LOGIN_URL % token
        data = urllib2.urlopen(url).read()

        crumb = data.split('\r\n')[1].split('=')[1]
        cookiey = data.split('\r\n')[2][2:]
        cookiet = data.split('\r\n')[3][2:]

        yhash = base64.b64encode(hashlib.md5(crumb + challenge).digest())
        yhash = yhash.replace('+', '.').replace('/', '_').replace('=', '-')

        return (cookiey, cookiet, yhash)

    def connectionMade(self):
        self.sessionid = 0
        self.buffer = ''
        self.sendPacket(YAHOO_SERVICE_HANDSHAKE, 0)

    def connectionLost(self, reason):
        print 'Disconnected: %s' % reason

    def sendPacket(self, service, status, data=[ ]):
        """ Sends a payload using specified service and status 
        Note: data should be a dictionary of data pairs """

        #print '<PacketOUT svc=%s, data=' % service, data, '>'

        payload = ""
        for pair in data:
            payload += YAHOO_PAIR_MARKER.join(pair) + YAHOO_PAIR_MARKER

        length = len(payload)
        buffer = "YMSG" # header start/magic marker
        buffer += "\x00\x10\x00\x00" # protocol version
        buffer += struct.pack('!HHLL', length, service, status, 
                              self.sessionid)
        buffer += payload
        self.transport.write(buffer)

    def receivePacket(self, service, status, data):
        """ receives parsed packet data from dataReceived """

        def key_data(key):
            for item in data:
                if item[0] == key:
                    return item[1]

        if service == YAHOO_SERVICE_PING:
            self.sendPacket(YAHOO_SERVICE_PING, 0)

        elif service == YAHOO_SERVICE_HANDSHAKE:
            payload = [ ('1', self.username) ]
            self.sendPacket(YAHOO_SERVICE_AUTH, 0, payload)

        elif service == YAHOO_SERVICE_AUTH:
            challenge = key_data('94')
            result = self.webLogin(challenge)
            if result:
                payload = [ ('1', self.username),
                            ('0', self.username),
                            ('277', result[0]),
                            ('278', result[1]),
                            ('307', result[2]),
                            ('244', '2097087'),
                            ('2', self.username),
                            ('2', '1'),
                            ('98', 'us'),
                            ('135', '9.0.0.2162') ]
                self.sendPacket(YAHOO_SERVICE_AUTHRESP, 0, payload)
                # for some reason, sending any IM here makes the server
                # responsive to outgoing notification events, otherwise
                # it ignores them until after another sendMessage()
                self.sendMessage(self.username, 'test')
                # now show as online
                self.receiveOnline()

        elif service == YAHOO_SERVICE_BUDDYLIST:
            pass

        elif service == YAHOO_SERVICE_NOTIFY:
            if key_data('13') == '1':
                is_typing = True
            else:
                is_typing = False
            user = key_data('4')
            self.receiveTypingNotify(user, is_typing)

        elif service == YAHOO_SERVICE_MESSAGE:
            sender = key_data('4')
            message = key_data('14')
            self.receiveMessage(sender, message)

        elif service == YAHOO_SERVICE_BUDDYAUTH:
            sender = key_data('4')
            self.receiveBuddyRequest(sender)

        #else:
            #print '<PacketIN svc=%s, data=' % (service, status), data

    def dataReceived(self, data):
        """ Receives raw data and extracts individual YMSG packets """
        self.buffer += data

        if len(self.buffer) < 20:
            return

        magic = self.buffer[:4]
        if not magic == "YMSG":
            # bad header, remove data from buffer until we get to
            # valid magic marker or buffer is empty
            print 'bad header'
            return

        while len(self.buffer) >= 20:
            header = struct.unpack('!LLHHLL', self.buffer[:20])
            length = header[2]
            payload = [ ]

            if length > 0:
                if len(self.buffer) < length+20:
                    return # received header but incomplete data
                data = self.buffer[20:length+20]
                items = data.split(YAHOO_PAIR_MARKER)
                while items:
                    if len(items) > 1:
                        payload.append((items[0], items[1]))
                        items.remove(items[1])
                    items.remove(items[0])

            self.sessionid = header[5]
            self.receivePacket(header[3], header[4], payload)
            self.buffer = self.buffer[length+20:]

    def disconnect(self):
        def f(reason): pass
        self.connectionLost = f
        self.transport.loseConnection()

    def sendMessage(self, user, message):
        """ Send an IM to specified user """
        payload = [ ('0', self.username),
                    ('1', self.username),
                    ('5', user),
                    ('14', message) ]
        self.sendPacket(YAHOO_SERVICE_MESSAGE, 0, payload)

    def notifyTyping(self, user, is_typing=True):
        """ Send the typing notification to specified user """
        if is_typing:
            is_typing = '1'
        else:
            is_typing = '0'

        payload = [ ('49', 'TYPING'),
                    ('1', self.username.lower()),
                    ('14', ' '),
                    ('13', is_typing),
                    ('5', user) ]
        self.sendPacket(YAHOO_SERVICE_NOTIFY, 0, payload)

    def acceptBuddyRequest(self, user):
        """ Accept a friend authorization from specified user """
        payload = [ ('1', self.username),
                    ('5', user),
                    ('13', '1') ]
        self.sendPacket(YAHOO_SERVICE_BUDDYAUTH, 0, payload)

    def error(self, code):
        pass

    def receiveOnline(self):
        pass

    def receiveMessage(self, user, message):
        pass

    def receiveBuddyRequest(self, user):
        pass

    def receiveTypingNotify(self, user, is_typing):
        pass

