import multiprocessing
from pathlib import Path
import sys
import tempfile
import unittest

from steamboat_connector.c2_route_pool import C2RoutePool, RoutePoolError
from steamboat_connector.validation import new_id


def route(i):
    account=new_id("acct")
    return {"tenant_account_id":account,"coordinator_account_id":account,"coordinator_device_id":new_id("dev"),"coordinator_serial":"serial-1","coordinator_key_hash":"a"*64,"coordinator_credential_epoch":1,"coordinator_boot_id":f"{i:032x}","request_id":new_id("req"),"session_id":new_id("ses"),"route_id":new_id("route"),"route_epoch":2,"attempt":1,"model_id":"model-v1"}

def member(i, component="worker1", role="host"):
    return {"selected_root_generation":f"{i:032x}","parent_boot_id":f"{i+100:032x}","role":role,"component":component,"worker_boot_id":f"{i+200:032x}","assignment_id":new_id("asg") if role=="host" else None,"credential_serial":f"serial-{i}","credential_key_hash":f"{i:064x}","credential_epoch":1,"admission_epoch":1}

def _reserve_process(path, allowed, rt, start, out):
    ledger=C2RoutePool(path, physical_host_id="f"*64, pool_id="pool", allowed_members=allowed)
    start.wait()
    try: ledger.reserve(rt, allowed[0]); out.put("ok")
    except RoutePoolError: out.put("full")


@unittest.skipUnless(sys.platform.startswith("linux"), "C2 storage uses Linux openat and flock")
class C2RoutePoolTests(unittest.TestCase):
    def create(self, path, allowed): return C2RoutePool(path, physical_host_id="f"*64, pool_id="pool", allowed_members=allowed)

    def test_coordinator_counts_once_and_release_is_exact_and_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            ms=[member(i, f"worker{i}") for i in (1,2,3)] + [member(4,"coordinator","personal_coordinator")]
            l=self.create(Path(d)/"state",ms); r=route(1)
            leases=[l.reserve(r,m) for m in ms]
            self.assertEqual(len(l.snapshot()["routes"]),1)
            self.assertEqual(sum(len(x["members"]) for x in l.snapshot()["routes"].values()),4)
            with self.assertRaises(RoutePoolError): l.release(leases[0], actual_reclamation_confirmed=None)
            self.assertTrue(l.release(leases[0], actual_reclamation_confirmed=True))
            self.assertFalse(l.release(leases[0], actual_reclamation_confirmed=True))
            with self.assertRaises(RoutePoolError): l.reserve(r,ms[0])

    def test_changed_member_identity_cannot_borrow_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); l=self.create(Path(d)/"state",[m]); r=route(1); receipt=l.reserve(r,m)
            changed=dict(m, selected_root_generation="9"*32)
            with self.assertRaises(RoutePoolError): l.reserve(r,changed)
            with self.assertRaises(RoutePoolError): l.release(dict(receipt, member_key="0"*20), actual_reclamation_confirmed=True)

    def test_ninth_live_route_rejected_and_reopen_preserves_state(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); path=Path(d)/"state"; l=self.create(path,[m])
            receipts=[l.reserve(route(i),m) for i in range(1,9)]
            with self.assertRaises(RoutePoolError): l.reserve(route(9),m)
            l=self.create(path,[m]); self.assertEqual(len(l.snapshot()["routes"]),8)
            for rec in receipts: l.release(rec,actual_reclamation_confirmed=True)

    def test_cross_process_ninth_route_race_has_one_winner(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); path=Path(d)/"state"; l=self.create(path,[m])
            held=[l.reserve(route(i),m) for i in range(1,8)]
            context=multiprocessing.get_context("spawn"); start=context.Event(); out=context.Queue()
            children=[context.Process(target=_reserve_process,args=(path,[m],route(i),start,out)) for i in (8,9)]
            try:
                for p in children:p.start()
                start.set(); results=[out.get(timeout=10) for _ in children]
                for p in children:p.join(10); self.assertEqual(p.exitcode,0)
                self.assertEqual(results.count("ok"),1); self.assertEqual(results.count("full"),1)
            finally:
                for p in children:
                    if p.is_alive():p.terminate()
                    p.join(2)

    def test_config_change_and_corrupt_oversize_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"state"; m=member(1); self.create(path,[m])
            with self.assertRaises(RoutePoolError): self.create(path,[member(2)])
            (path/"c2-route-pool-v2.json").write_bytes(b"x"*131073)
            with self.assertRaises(RoutePoolError): self.create(path,[m])

    def test_exact_types_and_route_schema(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); l=self.create(Path(d)/"state",[m]); r=route(1); r["attempt"]=True
            with self.assertRaises(RoutePoolError): l.reserve(r,m)


if __name__ == "__main__": unittest.main()
