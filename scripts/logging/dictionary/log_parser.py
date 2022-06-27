#!/usr/bin/env python3

from watchfiles import run_process

from log_parser_subproc import parse_args, main

if __name__ == "__main__":
    args = parse_args()
    run_process(args.dbfile, target=main, args=(args,))
