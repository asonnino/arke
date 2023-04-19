# Copyright(C) Facebook, Inc. and its affiliates.
from os.path import join

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cargo build --quiet --release --features benchmark'

    @staticmethod
    def generate_key(filename):
        assert isinstance(filename, str)
        return f'./authority keys --filename {filename}'

    @staticmethod
    def run_shard(keys, shard, committee, store, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(store, str)
        assert isinstance(shard, int)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (
            f'./authority {v} run --keys {keys} --committee {committee} '
            f'--storage {store} --shard {shard} --epoch 1'
        )

    @staticmethod
    def run_client(shard, committee, rate, size, faults, debug=False):
        assert isinstance(shard, int)
        assert isinstance(committee, str)
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(size, int) and rate >= 0
        assert isinstance(faults, int) and rate >= 0
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (
            f'./benchmark_client {v} --target-shard {shard} --committee {committee} '
            f'--rate {rate} --size {size} --faults {faults}'
        )

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node = join(origin, 'authority')
        client = join(origin, 'benchmark_client')
        return (
            'rm authority ; rm benchmark_client '
            f'; ln -s {node} . ; ln -s {client} .'
        )
