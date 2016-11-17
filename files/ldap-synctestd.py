#!/usr/bin/python3
import asyncio
import configparser
import logging
import os
import time
import socket
import signal
import sys

import ldap3

from datetime import datetime

logger = logging.getLogger("main")

try:
    asyncio.ensure_future = getattr(asyncio, "async")
except AttributeError:
    pass


class Main:
    def __init__(self, cfg):
        super().__init__()
        self.host = cfg.get("ldap", "host")
        self.port = cfg.getint("ldap", "port", fallback=389)
        self.auth_dn = cfg.get("ldap", "dn")
        self.password = cfg.get("ldap", "password")

        self.ctr_dn = cfg.get("counter", "dn")
        self.update_rate = cfg.getint("counter", "update_rate", fallback=1)

        self.listen_addr = cfg.get("service", "listen_addr", fallback=None)
        self.listen_port = cfg.getint("service", "listen_port", fallback=15878)

    def bind_connection(self):
        logger.debug("connecting to %r:%d as %r",
                     self.host,
                     self.port,
                     self.auth_dn)

        conn = ldap3.Connection(
            ldap3.Server(self.host, self.port),
            user=self.auth_dn,
            password=self.password
        )

        try:
            if not conn.bind():
                raise RuntimeError(
                    "failed to bind to LDAP server: {!r}".format(
                        conn.result,
                    )
                )
        except:
            conn.unbind()
            raise

        return conn

    @asyncio.coroutine
    def client_handler(self, client_reader, client_writer):
        logger.debug("inbound connection")
        sock = client_writer.transport.get_extra_info("socket")
        # we don’t want to receive data
        sock.shutdown(socket.SHUT_RD)

        try:
            ctr = self.read_counter()
            now = datetime.utcnow().timestamp()

            client_writer.write(
                "{}".format(round(now-ctr)).encode("ascii")
            )
            yield from client_writer.drain()
        finally:
            if client_writer.can_write_eof():
                client_writer.write_eof()
            client_writer.close()

    def connected_cb(self, client_reader, client_writer):
        asyncio.ensure_future(self.client_handler(
            client_reader,
            client_writer
        ))

    def read_counter(self):
        conn = self.bind_connection()
        try:
            if not conn.search(
                    self.ctr_dn,
                    "(objectClass=genericCounter)",
                    ldap3.SEARCH_SCOPE_BASE_OBJECT,
                    attributes=[
                        "counterValue",
                    ]):
                raise RuntimeError("failed to read counter")

            counter = int(conn.response[0]["attributes"]["counterValue"][0])
            logger.debug("read counter value: %d", counter)
            return counter
        finally:
            conn.unbind()

    @asyncio.coroutine
    def run(self, loop):
        interrupt_event = asyncio.Event()
        loop.add_signal_handler(signal.SIGINT, interrupt_event.set)
        loop.add_signal_handler(signal.SIGTERM, interrupt_event.set)

        server = yield from asyncio.start_server(
            self.connected_cb,
            host=self.listen_addr,
            port=self.listen_port,
            loop=loop,
        )

        try:
            yield from interrupt_event.wait()
            interrupt_event.clear()
        finally:
            server.close()
            _, pending = yield from asyncio.wait(
                [
                    server.wait_closed(),
                    interrupt_event.wait()
                ],
                return_when=asyncio.FIRST_COMPLETED
            )


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        dest="verbosity",
        help="Increase verbosity (up to -vvv)"
    )

    parser.add_argument(
        "config",
        type=argparse.FileType("r"),
        help="Configuration file",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="{}:%(name)s %(levelname)-5s %(message)s".format(
            os.path.basename(sys.argv[0])
        ),
        level={
            0: logging.ERROR,
            1: logging.WARNING,
            2: logging.INFO,
        }.get(args.verbosity, logging.DEBUG)
    )

    cfg = configparser.ConfigParser()
    cfg.read_file(args.config)

    impl = Main(cfg)

    try:
        logger.info("testing LDAP connection")
        impl.read_counter()
    except RuntimeError as exc:
        logger.exception("LDAP connection failed")
        sys.exit(2)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            impl.run(loop),
        )
    finally:
        loop.close()


if __name__ == "__main__":
    main()
