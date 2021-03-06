#!/usr/bin/env python3
#
# Copyright (c) 2021 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
Log Parser for Dictionary-based Logging

This uses the JSON database file to decode the input binary
log data and print the log messages.
"""

import argparse
import binascii
import logging
import sys

import serial

import dictionary_parser
from dictionary_parser.log_database import LogDatabase

tgt_logger = logging.getLogger("target")
logger = logging.getLogger("parser")

LOG_HEX_SEP = "##ZLOGV1##"


def parse_args():
    """Parse command line arguments"""
    argparser = argparse.ArgumentParser()

    argparser.add_argument("dbfile", help="Dictionary Logging Database file")
    argparser.add_argument("logfile", help="Log Data file")
    argparser.add_argument("--hex", action="store_true",
                           help="Log Data file is in hexadecimal strings")
    argparser.add_argument("--rawhex", action="store_true",
                           help="Log file only contains hexadecimal log data")
    argparser.add_argument("--debug", action="store_true",
                           help="Print extra debugging information")
    argparser.add_argument("-b", "--baud", default=115200, type=int,
                           help="Baudrate for serial port")

    return argparser.parse_args()


def read_log_file(args):
    """
    Read the log from file
    """
    logdata = None

    # Open log data file for reading
    if args.hex:
        if args.rawhex:
            # Simply log file with only hexadecimal data
            logdata = dictionary_parser.utils.convert_hex_file_to_bin(args.logfile)
        else:
            hexdata = ''

            with open(args.logfile, "r", encoding="iso-8859-1") as hexfile:
                for line in hexfile.readlines():
                    hexdata += line.strip()

            if LOG_HEX_SEP not in hexdata:
                logger.error("ERROR: Cannot find start of log data, exiting...")
                sys.exit(1)

            idx = hexdata.index(LOG_HEX_SEP) + len(LOG_HEX_SEP)
            hexdata = hexdata[idx:]

            if len(hexdata) % 2 != 0:
                # Make sure there are even number of characters
                idx = int(len(hexdata) / 2) * 2
                hexdata = hexdata[:idx]

            idx = 0
            while idx < len(hexdata):
                # When running QEMU via west or ninja, there may be additional
                # strings printed by QEMU, west or ninja (for example, QEMU
                # is terminated, or user interrupted, etc). So we need to
                # figure out where the end of log data stream by
                # trying to convert from hex to bin.
                idx += 2

                try:
                    binascii.unhexlify(hexdata[:idx])
                except binascii.Error:
                    idx -= 2
                    break

            logdata = binascii.unhexlify(hexdata[:idx])
    else:
        logfile = open(args.logfile, "rb")
        if not logfile:
            logger.error("ERROR: Cannot open binary log data file: %s, exiting...", args.logfile)
            sys.exit(1)

        logdata = logfile.read()

        logfile.close()

    return logdata


class LogStreamer:
    def __init__(self, args):
        self.hex = args.hex
        self._open(args.logfile, args.baud, args.hex)
        if self.hex and not args.rawhex:
            self._find_sentinel()

    def _open(self, path, baud, is_hex):
        self.is_serial = False
        try:
            self.fh = serial.Serial(port=path, baudrate=baud)
            self.is_serial = True
        except serial.SerialException:
            if is_hex:
                self.fh = open(path, "r", encoding="iso-8859-1")
            else:
                self.fh = open(path, "rb")


    def _find_sentinel(self):
        buf = ""
        while buf != LOG_HEX_SEP:
            if len(buf) == len(LOG_HEX_SEP):
                buf = buf[1:]
            buf += self.fh.read(1)


    def read(self, size):
        sz = size * 2 if self.hex else size
        if self.is_serial:
            buf = self.fh.read(size=sz)
        else:
            buf = self.fh.read(sz)
        if self.hex:
            try:
                return bytes.fromhex(buf)
            except ValueError:
                return b""
        else:
            return buf


def main(args):
    """Main function of log parser"""

    # Setup logging for parser
    logging.basicConfig(level="NOTSET", format="%(message)s", handlers=dictionary_parser.get_log_handlers())
    if args.debug:
        logger.setLevel(logging.DEBUG)
        tgt_logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        tgt_logger.setLevel(logging.INFO)

    # Read from database file
    database = LogDatabase.read_json_database(args.dbfile)
    if database is None:
        logger.error("ERROR: Cannot open database file: %s, exiting...", args.dbfile)
        sys.exit(1)

    try:
        logstream = LogStreamer(args)
    except:
        logger.error("ERROR: cannot read log from file: %s, exiting...", args.logfile)
        sys.exit(1)

    log_parser = dictionary_parser.get_parser(database)
    if log_parser is not None:
        logger.debug("# Build ID: %s", database.get_build_id())
        logger.debug("# Target: %s, %d-bit", database.get_arch(), database.get_tgt_bits())
        if database.is_tgt_little_endian():
            logger.debug("# Endianness: Little")
        else:
            logger.debug("# Endianness: Big")

        try:
            while True:
                log_parser.parse_log_data(logstream, debug=args.debug)
                if args.hex:
                    logstream._find_sentinel()
        except KeyboardInterrupt:
            pass
        # if not ret:
        #     logger.error("ERROR: there were error(s) parsing log data")
        #     sys.exit(1)
    else:
        logger.error("ERROR: Cannot find a suitable parser matching database version!")
        sys.exit(1)


if __name__ == "__main__":
    args = parse_args()
    main(args)
