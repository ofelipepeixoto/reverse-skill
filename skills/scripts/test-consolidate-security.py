#!/usr/bin/env python3
"""Synthetic memory-filesystem regressions; not an OS filesystem/TOCTOU test."""
import argparse
import ast
import contextlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import sys
from datetime import datetime, timezone

class MemoryPath:
    files = {}
    dirs = set()
    links = {}
    def __init__(self, value): self.path = PurePosixPath(str(value))
    def __str__(self): return str(self.path)
    def __truediv__(self, value): return MemoryPath(self.path / str(value))
    def resolve(self):
        value = os.path.normpath(str(self.path))
        for prefix, target in sorted(self.links.items(), key=lambda item: -len(item[0])):
            if value == prefix or value.startswith(prefix + '/'):
                value = target + value[len(prefix):]
                break
        return MemoryPath(value)
    def relative_to(self, other): return self.path.relative_to(str(other))
    def exists(self): return str(self.resolve()) in self.files or str(self.resolve()) in self.dirs
    def read_text(self, **kwargs): return self.files[str(self.resolve())]
    def write_text(self, value, **kwargs): self.files[str(self.resolve())] = value
    def mkdir(self, **kwargs): self.dirs.add(str(self.resolve()))

def run_tests(source):
    functions = ast.Module(body=[node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)], type_ignores=[])
    code = compile(functions, 'consolidate_evidence.py:functions', 'exec')
    cases = [
        ('valid', 'E-001', 'F-001', {}, 0),
        ('traversal', '../outside', 'F-001', {}, 1),
        ('absolute', '/case/outside', 'F-001', {}, 1),
        ('backslash', r'..\outside', 'F-001', {}, 1),
        ('duplicate', 'E-001,E-001', 'F-001', {}, 1),
        ('empty', '', 'F-001', {}, 1),
        ('finding-newline', 'E-001', 'F-001\n## synthetic', {}, 1),
        ('evidence-link', 'E-001', 'F-001', {'/case/evidence/E-001.md':'/case/outside.md'}, 1),
        ('evidence-dir-link', 'E-001', 'F-001', {'/case/evidence':'/outside'}, 1),
        ('report-dir-link', 'E-001', 'F-001', {'/case/report':'/outside'}, 1),
        ('report-file-link', 'E-001', 'F-001', {'/case/report/report.md':'/case/outside.md'}, 1),
        ('missing', 'E-404', 'F-001', {}, 1),
        ('metadata-newline', 'E-001', 'F-001', {}, 1),
    ]
    previous_argv = sys.argv
    try:
        for label, eid, fid, links, expected in cases:
            MemoryPath.files = {'/case/evidence/E-001.md':'### E-001\n- status: observed\n',
                                '/case/outside.md':'# synthetic unrelated file\n- status: observed\n'}
            MemoryPath.dirs = {'/case','/case/evidence'}
            MemoryPath.links = links
            before = dict(MemoryPath.files); before_dirs = set(MemoryPath.dirs)
            env = {'argparse':argparse, 're':re, 'sys':sys, 'datetime':datetime, 'timezone':timezone, 'Path':MemoryPath}
            exec(code, env)
            title = 'synthetic\n- status: validated' if label == 'metadata-newline' else 'synthetic'
            sys.argv = ['consolidate', '--case-root','/case','--evidence-ids',eid,
                        '--finding-id',fid,'--title',title,'--description','synthetic']
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = env['main']()
            assert result == expected, label
            if expected:
                assert MemoryPath.files == before and MemoryPath.dirs == before_dirs, label + ': unexpected write'
            else:
                assert '- status: candidate\n' in MemoryPath.files['/case/report/report.md']
                assert MemoryPath.files['/case/outside.md'] == before['/case/outside.md']
    finally:
        sys.argv = previous_argv
    print('CONSOLIDATE_SECURITY_OK cases=' + str(len(cases)) + ' memory filesystem only')

if __name__ == '__main__':
    run_tests(Path(__file__).with_name('consolidate_evidence.py').read_text(encoding='utf-8-sig'))
