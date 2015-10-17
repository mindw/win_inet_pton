import unittest

import win_inet_pton
import socket
import sys


class WinInetPtonTest(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, 'inet_pton'),
                         'test needs socket.inet_pton()')
    def testIPv4toString(self):
        from socket import inet_aton as f, inet_pton, AF_INET
        g = lambda a: inet_pton(AF_INET, a)

        assertInvalid = lambda func, a: self.assertRaises(
            socket.error, func, a
        )

        self.assertEqual(b'\x00\x00\x00\x00', f('0.0.0.0'))
        self.assertEqual(b'\xff\x00\xff\x00', f('255.0.255.0'))
        self.assertEqual(b'\xaa\xaa\xaa\xaa', f('170.170.170.170'))
        self.assertEqual(b'\x01\x02\x03\x04', f('1.2.3.4'))
        self.assertEqual(b'\xff\xff\xff\xff', f('255.255.255.255'))
        self.assertEqual(b'\x00\x00\x00\x00', f(u'0.0.0.0'))
        self.assertEqual(b'\xff\x00\xff\x00', f(u'255.0.255.0'))
        self.assertEqual(b'\xaa\xaa\xaa\xaa', f(u'170.170.170.170'))
        self.assertEqual(b'\x01\x02\x03\x04', f(u'1.2.3.4'))
        self.assertEqual(b'\xff\xff\xff\xff', f(u'255.255.255.255'))
        assertInvalid(f, '0.0.0.')
        assertInvalid(f, '300.0.0.0')
        assertInvalid(f, 'a.0.0.0')
        assertInvalid(f, '1.2.3.4.5')
        assertInvalid(f, '::1')

        self.assertEqual(b'\x00\x00\x00\x00', g('0.0.0.0'))
        self.assertEqual(b'\xff\x00\xff\x00', g('255.0.255.0'))
        self.assertEqual(b'\xaa\xaa\xaa\xaa', g('170.170.170.170'))
        self.assertEqual(b'\xff\xff\xff\xff', g('255.255.255.255'))
        self.assertEqual(b'\x00\x00\x00\x00', g(u'0.0.0.0'))
        self.assertEqual(b'\xff\x00\xff\x00', g(u'255.0.255.0'))
        self.assertEqual(b'\xaa\xaa\xaa\xaa', g(u'170.170.170.170'))
        self.assertEqual(b'\xff\xff\xff\xff', g(u'255.255.255.255'))
        assertInvalid(g, '0.0.0.')
        assertInvalid(g, '300.0.0.0')
        assertInvalid(g, 'a.0.0.0')
        assertInvalid(g, '1.2.3.4.5')
        assertInvalid(g, '::1')

    @unittest.skipUnless(hasattr(socket, 'inet_pton'),
                         'test needs socket.inet_pton()')
    def testIPv6toString(self):
        try:
            from socket import inet_pton, AF_INET6, has_ipv6
            if not has_ipv6:
                self.skipTest('IPv6 not available')
        except ImportError:
            self.skipTest('could not import needed symbols from socket')

        if sys.platform == "win32":
            try:
                inet_pton(AF_INET6, '::')
            except socket.error as e:
                if e.winerror == 10022:
                    self.skipTest('IPv6 might not be supported')

        f = lambda a: inet_pton(AF_INET6, a)
        assertInvalid = lambda a: self.assertRaises(
            socket.error, f, a
        )

        self.assertEqual(b'\x00' * 16, f('::'))
        self.assertEqual(b'\x00' * 16, f('0::0'))
        self.assertEqual(b'\x00\x01' + b'\x00' * 14, f('1::'))
        self.assertEqual(
            b'\x45\xef\x76\xcb\x00\x1a\x56\xef\xaf\xeb\x0b\xac\x19\x24\xae\xae',
            f('45ef:76cb:1a:56ef:afeb:bac:1924:aeae')
        )
        self.assertEqual(
            b'\xad\x42\x0a\xbc' + b'\x00' * 4 + b'\x01\x27\x00\x00\x02\x54\x00\x02',
            f('ad42:abc::127:0:254:2')
        )
        self.assertEqual(b'\x00\x12\x00\x0a' + b'\x00' * 12, f('12:a::'))
        assertInvalid('0x20::')
        assertInvalid(':::')
        assertInvalid('::0::')
        assertInvalid('1::abc::')
        assertInvalid('1::abc::def')
        assertInvalid('1:2:3:4:5:6:')
        assertInvalid('1:2:3:4:5:6')
        assertInvalid('1:2:3:4:5:6:7:8:')
        assertInvalid('1:2:3:4:5:6:7:8:0')

        self.assertEqual(
            b'\x00' * 12 + b'\xfe\x2a\x17\x40', f('::254.42.23.64')
        )
        self.assertEqual(
            b'\x00\x42' + b'\x00' * 8 + b'\xa2\x9b\xfe\x2a\x17\x40',
            f('42::a29b:254.42.23.64')
        )
        self.assertEqual(
            b'\x00\x42\xa8\xb9\x00\x00\x00\x02\xff\xff\xa2\x9b\xfe\x2a\x17\x40',
            f('42:a8b9:0:2:ffff:a29b:254.42.23.64')
        )
        assertInvalid('255.254.253.252')
        assertInvalid('1::260.2.3.0')
        assertInvalid('1::0.be.e.0')
        assertInvalid('1:2:3:4:5:6:7:1.2.3.4')
        assertInvalid('::1.2.3.4:0')
        assertInvalid('0.100.200.0:3:4:5:6:7:8')

    @unittest.skipUnless(hasattr(socket, 'inet_ntop'),
                         'test needs socket.inet_ntop()')
    def testStringToIPv4(self):
        from socket import inet_ntoa as f, inet_ntop, AF_INET
        g = lambda a: inet_ntop(AF_INET, a)
        assertInvalid = lambda func,a: self.assertRaises(
            socket.error, func, a
        )

        self.assertEqual('1.0.1.0', f(b'\x01\x00\x01\x00'))
        self.assertEqual('170.85.170.85', f(b'\xaa\x55\xaa\x55'))
        self.assertEqual('255.255.255.255', f(b'\xff\xff\xff\xff'))
        self.assertEqual('1.2.3.4', f(b'\x01\x02\x03\x04'))
        assertInvalid(f, b'\x00' * 3)
        assertInvalid(f, b'\x00' * 5)
        assertInvalid(f, b'\x00' * 16)
        # self.assertEqual('170.85.170.85', f(bytearray(b'\xaa\x55\xaa\x55')))

        self.assertEqual('1.0.1.0', g(b'\x01\x00\x01\x00'))
        self.assertEqual('170.85.170.85', g(b'\xaa\x55\xaa\x55'))
        self.assertEqual('255.255.255.255', g(b'\xff\xff\xff\xff'))
        assertInvalid(g, b'\x00' * 3)
        assertInvalid(g, b'\x00' * 5)
        assertInvalid(g, b'\x00' * 16)
        # self.assertEqual('170.85.170.85', g(bytearray(b'\xaa\x55\xaa\x55')))

    @unittest.skipUnless(hasattr(socket, 'inet_ntop'),
                         'test needs socket.inet_ntop()')
    def testStringToIPv6(self):
        try:
            from socket import inet_ntop, AF_INET6, has_ipv6
            if not has_ipv6:
                self.skipTest('IPv6 not available')
        except ImportError:
            self.skipTest('could not import needed symbols from socket')

        if sys.platform == "win32":
            try:
                inet_ntop(AF_INET6, b'\x00' * 16)
            except socket.error as e:
                if e.winerror == 10022:
                    self.skipTest('IPv6 might not be supported')

        f = lambda a: inet_ntop(AF_INET6, a)
        assertInvalid = lambda a: self.assertRaises(
            socket.error, f, a
        )

        self.assertEqual('::', f(b'\x00' * 16))
        self.assertEqual('::1', f(b'\x00' * 15 + b'\x01'))
        self.assertEqual(
            'aef:b01:506:1001:ffff:9997:55:170',
            f(b'\x0a\xef\x0b\x01\x05\x06\x10\x01\xff\xff\x99\x97\x00\x55\x01\x70')
        )
        # self.assertEqual('::1', f(bytearray(b'\x00' * 15 + b'\x01')))

        assertInvalid(b'\x12' * 15)
        assertInvalid(b'\x12' * 17)
        assertInvalid(b'\x12' * 4)


if __name__ == '__main__':
    unittest.main()
