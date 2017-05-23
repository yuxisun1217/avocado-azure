#!/usr/bin/python

import argparse
import pprint
import signal
import stomp
import sys
import os

conn = None


def parse_args():
    "Parse command line arguments."
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Subscribe to the Red Hat CI message bus.'
    )
    parser.add_argument(
        '--user',
        dest='user',
        metavar='<user>',
        required=True,
        help='Username to use to connect to the message bus.'
    )
    parser.add_argument(
        '--password',
        dest='password',
        metavar='<password>',
        required=True,
        help='Password to use to connect to the message bus.'
    )
    parser.add_argument(
        '--selector',
        dest='selector',
        metavar='<JMS selector>',
        help='JMS selector for filtering messages.'
    )
    parser.add_argument(
        '--host',
        dest='host',
        metavar='<host>',
        default='ci-bus.lab.eng.rdu2.redhat.com',
        help='Message bus host.'
    )
    parser.add_argument(
        '--port',
        dest='port',
        metavar='<port>',
        type=int,
        default=61613,
        help='Message bus port.'
    )
    parser.add_argument(
        '--destination',
        dest='destination',
        metavar='<destination>',
        default='/topic/CI',
        help='Message bus topic/subscription.'
    )
    parser.add_argument(
        '--count',
        dest='count',
        metavar='<count>',
        type=int,
        default=0,
        help='Limit number of messages to catch. 0 for unlimited'
    )
    return parser.parse_args()


def signal_handler(signal, frame):
    print('Terminating subscription.')
    conn.disconnect()
    sys.exit(0)


class CIListener(object):
    def __init__(self, count):
        if count <= 0:
            count = float('inf')
        self.count = count

    def on_error(self, headers, message):
        print("=" * 72)
        print('RECEIVED AN ERROR.')
        print('Message headers:')
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(headers)
        print('Message body:')
        print(message)

    def on_message(self, headers, message):
        print("=" * 72)
        print('Message headers:')
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(headers)
        print('Message body:')
        print(message)
        self.count -= 1
        if self.count <= 0:
            # Send signal to terminate main thread
            os.kill(os.getpid(), signal.SIGINT)


def main():
    # Create a subscription to the CI message bus.
    global conn

    args = parse_args()
    conn = stomp.Connection([(args.host, args.port)])
    conn.set_listener('CI Listener', CIListener(args.count))
    conn.start()
    conn.connect(login=args.user, passcode=args.password)

    if (args.selector):
        conn.subscribe(
            destination=args.destination,
            id=1,
            ack='auto',
            headers={'selector': args.selector}
        )
    else:
        conn.subscribe(
            destination=args.destination,
            id=1,
            ack='auto'
        )

    print('Press Ctrl+C to exit.')
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()

if __name__ == '__main__':
    main()
