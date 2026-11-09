"""Finite publication checks with self-authored synthetic data, never Nikon input."""
from pathlib import Path
import csv
import importlib.util
import json
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/prototypes'))
from status_count_sink import ACCEPTED_BRANCH_CODE,HostAssumptions,Reply,SyntheticLease,transfer
from storage_span_plan import plan

class PublicationTests(unittest.TestCase):
    def test_remote_gate_requires_empty_branches_and_tags(self):
        spec=importlib.util.spec_from_file_location('publication_manager',ROOT/'publication-tools/sync.py')
        manager=importlib.util.module_from_spec(spec);spec.loader.exec_module(manager)
        for code,branches,tags,accepted in [(409,[],[],True),(404,[],[],True),(409,[{'name':'other'}],[],False),(409,[],[{'name':'tag'}],False),(403,[],[],False)]:
            with self.subTest(code=code,branches=branches,tags=tags):
                responses=[SimpleNamespace(returncode=1,stdout='',stderr=f'gh: response (HTTP {code})')]
                if code in (404,409):
                    responses.extend(SimpleNamespace(returncode=0,stdout=json.dumps(v),stderr='') for v in (branches,tags))
                with patch.object(manager,'call',side_effect=responses) as remote:
                    if accepted:manager.verify_remote_base(Path('unused-fixture'),'fixture-gh','fixture-owner/fixture-repo')
                    else:
                        with self.assertRaises(RuntimeError):manager.verify_remote_base(Path('unused-fixture'),'fixture-gh','fixture-owner/fixture-repo')
                    self.assertEqual(remote.call_count,3 if code in (404,409) else 1)
        for ancestor in (True,False):
            with self.subTest(existing_main_is_local_ancestor=ancestor):
                with patch.object(manager,'call',return_value=SimpleNamespace(returncode=0,stdout='a'*40,stderr='')),patch.object(manager,'git',return_value=SimpleNamespace(returncode=0 if ancestor else 1)):
                    if ancestor:manager.verify_remote_base(Path('unused-fixture'),'fixture-gh','fixture-owner/fixture-repo')
                    else:
                        with self.assertRaises(RuntimeError):manager.verify_remote_base(Path('unused-fixture'),'fixture-gh','fixture-owner/fixture-repo')

    def test_synthetic_codes_survive_short_writes(self):
        codes=list(range(1024));data=struct.pack('<1024H',*codes);output=bytearray()
        def callback(descriptor,wanted,view):
            kind,address,reserved=struct.unpack('<III',descriptor)
            self.assertEqual((kind,address,reserved),(1,4096+len(output),0))
            count=min(wanted,31);output.extend(view[:count]);return Reply(ACCEPTED_BRANCH_CODE,count)
        lease=SyntheticLease(data);result=transfer(lease,4096,callback,HostAssumptions(True,True))
        self.assertTrue(result.completed);self.assertTrue(lease.released)
        self.assertEqual(bytes(output),data);self.assertEqual(struct.unpack('<1024H',output),tuple(codes));self.assertGreater(result.calls,1)

    def test_error_partial_count_never_replays(self):
        calls=[]
        def callback(*args):calls.append(args);return Reply(1,7)
        lease=SyntheticLease(b'self-authored-fixture')
        first=transfer(lease,4096,callback,HostAssumptions(True,True))
        second=transfer(lease,4096,callback,HostAssumptions(True,True))
        self.assertFalse(first.completed);self.assertFalse(second.completed)
        self.assertFalse(lease.released);self.assertEqual(len(calls),1)

    def test_missing_contract_prevents_first_call(self):
        calls=[];lease=SyntheticLease(b'fixture')
        result=transfer(lease,4096,lambda *a:calls.append(a))
        self.assertFalse(result.completed);self.assertEqual(calls,[]);self.assertFalse(lease.released)

    def test_block_padding_and_conditional_helper_extent(self):
        direct=plan(513);bounce=plan(513,pointer=0x20000001)
        self.assertEqual(direct['transfer_span'],1024);self.assertEqual(direct['block_padding'],511)
        self.assertEqual(bounce['source_request_extent'],4096)
        self.assertEqual(bounce['potential_request_tail_past_transfer'],3072)

    def test_partial_types_have_valid_bounds(self):
        for s in json.loads((ROOT/'indexes/structures.json').read_text()):
            for f in s['fields']:
                self.assertGreater(f['size'],0);self.assertGreaterEqual(f['offset'],0)
                self.assertLessEqual(f['offset']+f['size'],s['length'])

    def test_components_and_evidence_are_not_merged(self):
        recipe=json.loads((ROOT/'indexes/annotation-recipe.json').read_text())['components']
        self.assertEqual(set(recipe),{'MAS','SLA','EX'})
        self.assertEqual(recipe['MAS']['base'],recipe['SLA']['base'])
        self.assertNotEqual(recipe['MAS']['sha256'],recipe['SLA']['sha256'])
        with (ROOT/'indexes/nodes.csv').open() as f:
            nodes={(r['component'],r['id']) for r in csv.DictReader(f)}
        with (ROOT/'indexes/relations.csv').open() as f:
            for e in csv.DictReader(f):
                self.assertIn(e['grade'],('VERIFIED','INFERRED','UNKNOWN'))
                self.assertIn((e['component'],e['source']),nodes);self.assertIn((e['component'],e['target']),nodes)

if __name__=='__main__':unittest.main()
