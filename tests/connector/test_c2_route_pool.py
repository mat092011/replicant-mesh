import multiprocessing
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

from steamboat_connector.c2_route_pool import C2RoutePool, RoutePoolError, project_host_scope_member
from steamboat_connector.validation import new_id


def route(i):
    account=new_id("acct")
    return {"tenant_account_id":account,"coordinator_account_id":account,"coordinator_device_id":new_id("dev"),"coordinator_serial":"1a","coordinator_key_hash":"a"*64,"coordinator_credential_epoch":1,"coordinator_boot_id":f"{i:032x}","request_id":new_id("req"),"session_id":new_id("ses"),"route_id":new_id("route"),"route_epoch":1,"attempt":1,"model_id":"b"*64}

def member(i, component="worker-1", role="host"):
    return {"selected_root_generation":f"{i:064x}","parent_boot_id":f"{i+100:032x}","account_id":new_id("acct"),"device_id":new_id("dev"),"role":role,"component":component,"worker_boot_id":f"{i+200:032x}","assignment_id":new_id("asg") if role=="host" else None,"credential_serial":f"{i+1:x}","credential_key_hash":f"{i:064x}","credential_certificate_hash":f"{i:064x}","credential_epoch":1,"admission_epoch":1}

class C2ProjectionTests(unittest.TestCase):
    def test_fifth_selected_member_rejected_by_constructor_and_reconfiguration(self):
        members=[member(i, f"worker-{i}") for i in (1,2,3,4,5)]
        with self.assertRaisesRegex(RoutePoolError,"1..4"):
            C2RoutePool("unused",physical_host_id="f"*64,pool_id="pool",allowed_members=members)
        ledger=C2RoutePool.__new__(C2RoutePool)
        with self.assertRaisesRegex(RoutePoolError,"1..4"):
            ledger._configure("unused","f"*64,"pool",members,None)

    def test_verified_selected_scope_projection(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from steamboat_security.certificates import public_key_sha256
        from steamboat_security.clock import Clock
        from steamboat_security.root_c2_group_scope import sign_c2_host_group_policy, verify_c2_host_group_policy, PROFILE
        key=ec.generate_private_key(ec.SECP256R1())
        private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        raw={"version":1,"profile":PROFILE,"account_id":"acct_"+"1"*32,"device_id":"dev_"+"2"*32,"role":"host",
             "credential":{"serial":"a1","credential_epoch":2,"certificate_sha256":"a"*64,"public_key_sha256":"b"*64},
             "generation_sha256":"c"*64,"admission_epoch":3,"parent_boot_id":"4"*32,"model_id":"d"*64,
             "catalog_sha256":"e"*64,"catalog_public_key_sha256":"f"*64,"operator_public_key_sha256":public_key_sha256(key.public_key()),
             "components":[{"component":"worker-1","worker_boot_id":"5"*32,"assignment_id":"asg_"+"6"*32,"assignment_sha256":"7"*64,"channel_certificate_sha256":"8"*64,"channel_public_key_sha256":"9"*64}]}
        now=int(time.time()); payload={"version":1,"issued_at":now-1,"expires_at":now+100,"scope":raw}
        encoded=sign_c2_host_group_policy(payload,private)
        clock=Clock(wall=time.time,monotonic=time.monotonic,uncertainty_seconds=lambda:0.0)
        verified=verify_c2_host_group_policy(encoded,public,clock=clock)
        projected=project_host_scope_member(verified.scope,"worker-1")
        self.assertEqual(projected["selected_root_generation"],"c"*64)
        self.assertEqual(projected["credential_serial"],"a1")
        with self.assertRaises(RoutePoolError): project_host_scope_member(verified.scope,"worker-2")

    def test_exact_integer_bounds_are_validated_without_storage(self):
        from steamboat_connector.c2_route_pool import _validate_route, _validate_member
        rt=route(1); rt["coordinator_credential_epoch"]=2**63-1
        _validate_route(rt)
        rt["coordinator_credential_epoch"]=True
        with self.assertRaises(RoutePoolError): _validate_route(rt)
        m=member(1); m["credential_epoch"]=2**63-1; m["admission_epoch"]=2**63-1; m["credential_serial"]="f"*40
        _validate_member(m)
        m["admission_epoch"]=2**63
        with self.assertRaises(RoutePoolError): _validate_member(m)

    def test_full_eight_route_32_member_state_fits_fixed_128_kib_bound(self):
        from steamboat_connector.c2_route_pool import MAX_FILE_BYTES, VERSION, PROFILE
        from steamboat_connector.validation import json_bytes
        routes={}; allow=[]
        group=[member(10+j,f"worker-{j}") for j in (1,2,3)]+[member(14,"coordinator","personal_coordinator")]
        for m in group:
            m["credential_serial"]="f"*40; m["credential_epoch"]=m["admission_epoch"]=2**63-1
            allow.append(m)
        for i in range(1,9):
            coordinator=group[3]
            rt=route(i); rt.update(coordinator_account_id=coordinator["account_id"],tenant_account_id=coordinator["account_id"],coordinator_device_id=coordinator["device_id"],coordinator_serial="f"*40,coordinator_key_hash=coordinator["credential_key_hash"],coordinator_credential_epoch=2**63-1,coordinator_boot_id=coordinator["worker_boot_id"])
            rkey=__import__("hashlib").sha256(json_bytes(rt)).hexdigest(); selected={}
            for m in group:
                mkey=__import__("hashlib").sha256(json_bytes(m)).hexdigest()
                selected[mkey]={"member":m,"token":f"{i:064x}"[-64:],"released":False}
            routes[rkey]={"route":rt,"closed":False,"members":selected}
        config=__import__("hashlib").sha256(json_bytes({"physical_host_id":"f"*64,"pool_id":"pool","allowed_members":allow,"max_routes":8})).hexdigest()
        encoded=json_bytes({"version":VERSION,"profile":PROFILE,"config_digest":config,"routes":routes},maximum_bytes=MAX_FILE_BYTES)
        self.assertLessEqual(len(encoded),MAX_FILE_BYTES)

def _reserve_process(path, allowed, rt, ready, start, out):
    ledger=C2RoutePool(path, physical_host_id="f"*64, pool_id="pool", allowed_members=allowed)
    ready.put(True)
    start.wait()
    try: ledger.reserve(rt, allowed[0]); out.put("committed")
    except RoutePoolError as error: out.put("refused:"+str(error))
    except Exception as error: out.put("unexpected:"+type(error).__name__)


@unittest.skipUnless(sys.platform.startswith("linux"), "C2 storage uses Linux openat and flock")
class C2RoutePoolTests(unittest.TestCase):
    def create(self, path, allowed):
        path=Path(path); path.mkdir(mode=0o700,exist_ok=True); path.chmod(0o700)
        return C2RoutePool.provision(path, physical_host_id="f"*64, pool_id="pool", allowed_members=allowed)
    def open(self, path, allowed): return C2RoutePool(path, physical_host_id="f"*64, pool_id="pool", allowed_members=allowed)

    def test_coordinator_counts_once_and_release_is_exact_and_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            ms=[member(i, f"worker-{i}") for i in (1,2,3)] + [member(4,"coordinator","personal_coordinator")]
            l=self.create(Path(d)/"state",ms); r=route(1)
            r.update(coordinator_account_id=ms[3]["account_id"],tenant_account_id=ms[3]["account_id"],coordinator_device_id=ms[3]["device_id"],coordinator_boot_id=ms[3]["worker_boot_id"],coordinator_serial=ms[3]["credential_serial"],coordinator_key_hash=ms[3]["credential_key_hash"],coordinator_credential_epoch=ms[3]["credential_epoch"])
            leases=[l.reserve(r,m) for m in ms[:3]]
            self.assertEqual(l.reserve(r,ms[1]).receipt,leases[1].receipt)
            self.assertEqual(len(l.snapshot()["routes"]),1)
            self.assertEqual(sum(len(x["members"]) for x in l.snapshot()["routes"].values()),3)
            with self.assertRaises(RoutePoolError): l.release(leases[0].receipt, actual_reclamation_confirmed=None)
            self.assertTrue(l.release(leases[0].receipt, actual_reclamation_confirmed=True).released)
            self.assertFalse(l.release(leases[0].receipt, actual_reclamation_confirmed=True).released)
            self.assertEqual(l.reserve(r,ms[1]).receipt,leases[1].receipt)
            with self.assertRaises(RoutePoolError): l.reserve(r,ms[0])
            with self.assertRaisesRegex(RoutePoolError,"closing"):
                l.reserve(r,ms[3])

    def test_changed_member_identity_cannot_borrow_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); l=self.create(Path(d)/"state",[m]); r=route(1); receipt=l.reserve(r,m).receipt
            changed=dict(m, selected_root_generation="9"*32)
            with self.assertRaises(RoutePoolError): l.reserve(r,changed)
            with self.assertRaises(RoutePoolError): l.release(dict(receipt, member_key="0"*20), actual_reclamation_confirmed=True)

    def test_ninth_live_route_rejected_and_reopen_preserves_state(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); path=Path(d)/"state"; l=self.create(path,[m])
            receipts=[]
            for i in range(1,9):
                rt=route(i); receipts.append(l.reserve(rt,m).receipt)
            ninth=route(9)
            with self.assertRaisesRegex(RoutePoolError,"live route limit"): l.reserve(ninth,m)
            l=self.open(path,[m]); self.assertEqual(len(l.snapshot()["routes"]),8)
            for rec in receipts: l.release(rec,actual_reclamation_confirmed=True)

    def test_cross_process_ninth_route_race_has_one_winner(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); path=Path(d)/"state"; l=self.create(path,[m])
            held=[]
            for i in range(1,8):
                rt=route(i); held.append(l.reserve(rt,m).receipt)
            mp_context=multiprocessing.get_context("spawn"); start=mp_context.Event(); out=mp_context.Queue(); ready=mp_context.Queue()
            children=[mp_context.Process(target=_reserve_process,args=(path,[m],route(i),ready,start,out)) for i in (8,9)]
            try:
                for p in children:p.start()
                self.assertTrue(ready.get(timeout=10)); self.assertTrue(ready.get(timeout=10))
                start.set(); results=[out.get(timeout=10) for _ in children]
                for p in children:p.join(10); self.assertEqual(p.exitcode,0)
                self.assertEqual(results.count("committed"),1)
                self.assertEqual(sum(x.startswith("refused:") and "live route limit" in x for x in results),1)
                self.assertFalse(any(x.startswith("unexpected:") for x in results))
            finally:
                for p in children:
                    if p.is_alive():p.terminate()
                    p.join(2)

    def test_config_change_and_corrupt_oversize_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"state"; m=member(1); self.create(path,[m])
            with self.assertRaises(RoutePoolError): self.open(path,[member(2)])
            (path/"c2-route-pool-v2.json").write_bytes(b"x"*131073)
            with self.assertRaises(RoutePoolError): self.open(path,[m])

    def test_exact_types_and_route_schema(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); l=self.create(Path(d)/"state",[m]); r=route(1); r["attempt"]=True
            with self.assertRaises(RoutePoolError): l.reserve(r,m)

    def test_unknown_commit_fences_same_instance_other_instance_and_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); path=Path(d)/"state"; l=self.create(path,[m]); other=self.open(path,[m]); rt=route(1)
            from steamboat_connector import c2_route_pool as mod
            original=mod.atomic_write_private
            def commit_then_lose_ack(*args,**kwargs):
                original(*args,**kwargs)
                raise OSError("injected post-replace acknowledgement loss")
            with mock.patch.object(mod,"atomic_write_private",side_effect=commit_then_lose_ack):
                with self.assertRaises(RoutePoolError): l.reserve(rt,m)
            with self.assertRaises(RoutePoolError): l.snapshot()
            with self.assertRaises(RoutePoolError): other.snapshot()
            with self.assertRaises(RoutePoolError): self.open(path,[m])

    def test_post_unlink_fsync_failure_reports_confirmed_commit_and_cleanup_status(self):
        with tempfile.TemporaryDirectory() as d:
            m=member(1); path=Path(d)/"state"; l=self.create(path,[m]); other=self.open(path,[m]); rt=route(1)
            import steamboat_connector.c2_route_pool as mod
            original=mod.os.fsync; calls={"n":0}
            def fail_after_cleanup_sync(fd):
                calls["n"]+=1
                if calls["n"]==5: raise OSError("injected post-unlink directory fsync error")
                return original(fd)
            with mock.patch.object(mod.os,"fsync",side_effect=fail_after_cleanup_sync):
                result=l.reserve(rt,m)
            self.assertFalse(result.fence_cleanup_confirmed)
            self.assertEqual(len(other.snapshot()["routes"]),1)
            self.assertEqual(sum(len(x["members"]) for x in other.snapshot()["routes"].values()),1)
            # Duplicate reserve reports the same committed receipt, and cleanup
            # confirmation remains false until a directory fsync succeeds.
            original_fsync=mod.os.fsync
            with mock.patch.object(mod.os,"fsync",side_effect=OSError("retry cleanup fsync failure")):
                retry=l.reserve(rt,m)
            self.assertEqual(retry.receipt,result.receipt)
            self.assertFalse(retry.fence_cleanup_confirmed)
            retry=l.reserve(rt,m)
            self.assertEqual(retry.receipt,result.receipt)
            self.assertTrue(retry.fence_cleanup_confirmed)
            original_fsync=mod.os.fsync; calls={"n":0}
            def fail_release_cleanup(fd):
                calls["n"]+=1
                if calls["n"]==5: raise OSError("injected release cleanup fsync failure")
                return original_fsync(fd)
            with mock.patch.object(mod.os,"fsync",side_effect=fail_release_cleanup):
                released=l.release(result.receipt,actual_reclamation_confirmed=True)
            self.assertTrue(released.released)
            self.assertFalse(released.fence_cleanup_confirmed)
            with mock.patch.object(mod.os,"fsync",side_effect=OSError("retry release cleanup fsync failure")):
                repeated=l.release(result.receipt,actual_reclamation_confirmed=True)
            self.assertFalse(repeated.released)
            self.assertFalse(repeated.fence_cleanup_confirmed)
            repeated=l.release(result.receipt,actual_reclamation_confirmed=True)
            self.assertFalse(repeated.released)
            self.assertTrue(repeated.fence_cleanup_confirmed)
            self.assertEqual(sum(not x["released"] for rr in other.snapshot()["routes"].values() for x in rr["members"].values()),0)
            # If a pending marker reappears after a crash, all opens fail closed.
            pending=path/"c2-route-pool-v2.pending"
            pending.write_text('{"version":2,"profile":"physical_pool_route_membership_v2","config_digest":"'+'f'*64+'","transaction_id":"'+'a'*64+'"}')
            pending.chmod(0o600)
            with self.assertRaises(RoutePoolError): other.snapshot()

    def test_explicit_provision_only_and_nested_state_validation(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"state"; m=member(1); r=route(1)
            path.mkdir(mode=0o700); path.chmod(0o700)
            with self.assertRaises(RoutePoolError): self.open(path,[m])
            l=self.create(path,[m]); receipt=l.reserve(r,m).receipt
            with self.assertRaises(RoutePoolError): self.create(path,[m])
            state=l.snapshot(); route_record=next(iter(state["routes"].values()))
            entry=next(iter(route_record["members"].values())); entry["token"]="bad"
            (path/"c2-route-pool-v2.json").write_text(json.dumps(state,separators=(",",":")))
            with self.assertRaises(RoutePoolError): self.open(path,[m])

    def test_eight_routes_four_members_under_fixed_file_bound(self):
        with tempfile.TemporaryDirectory() as d:
            members=[member(i,f"worker-{i}") for i in (1,2,3)]+[member(4,"coordinator","personal_coordinator")]
            for m in members:
                m["credential_serial"]="f"*40
                m["credential_epoch"]=2**63-1
                m["admission_epoch"]=2**63-1
            l=self.create(Path(d)/"state",members)
            for i in range(1,9):
                rt=route(i)
                rt["coordinator_serial"]="f"*40
                rt["coordinator_credential_epoch"]=2**63-1
                coordinator=members[3]
                rt.update(coordinator_account_id=coordinator["account_id"],tenant_account_id=coordinator["account_id"],coordinator_device_id=coordinator["device_id"],coordinator_boot_id=coordinator["worker_boot_id"],coordinator_key_hash=coordinator["credential_key_hash"])
                for m in members: l.reserve(rt,m)
            self.assertEqual(sum(len(x["members"]) for x in l.snapshot()["routes"].values()),32)
            self.assertLessEqual((Path(d)/"state"/"c2-route-pool-v2.json").stat().st_size,131072)


if __name__ == "__main__": unittest.main()
