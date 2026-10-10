#!/usr/bin/env python3
import hashlib, json, os, shutil, subprocess, tempfile, time
from pathlib import Path

MAX_AGE = 4 * 60 * 60
FORBIDDEN_PUBLIC_NAMES = {".env", "package-lock.json", "package.json"}
SECRET_ENV = {"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "PRIVATE_SOURCE_TOKEN"}

def run(cwd, *args):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()

def sha256_file(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for chunk in iter(lambda:f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def tree_digest(root):
    rows=[]
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            rows.append(f"{p.relative_to(root).as_posix()}\0{sha256_file(p)}")
    return hashlib.sha256(("\n".join(rows)+"\n").encode()).hexdigest()

def git_identity(root):
    return run(root,"git","rev-parse","HEAD"), run(root,"git","rev-parse","HEAD^{tree}")

def make_receipt(root, status="PASS", age=0, head=None, tree=None):
    actual_head, actual_tree=git_identity(root)
    receipt={
      "schema":1,"executor":"GPT_ISOLATED_LINUX_CLOUD","status":status,"mode":"full",
      "head":head or actual_head,"tree":tree or actual_tree,
      "source_digest":tree_digest(root),
      "finished_at":int(time.time())-age,
      "gates":{"dependency_security":"PASS","ssg":"PASS","playwright":"62/62","lighthouse_mobile":"33/33","lighthouse_desktop":"33/33"}
    }
    return receipt

def independent_release_verify(source, receipt, expected_head, expected_tree, output):
    # Production verifier does not trust a prose/JSON PASS by itself.
    if any(os.environ.get(k) for k in SECRET_ENV):
        raise RuntimeError("verification phase must not receive deploy/private-source secrets")
    head, tree=git_identity(source)
    if head != expected_head: raise RuntimeError("HEAD mismatch")
    if tree != expected_tree: raise RuntimeError("tree mismatch")
    if receipt.get("status") != "PASS" or receipt.get("mode") != "full": raise RuntimeError("receipt not full PASS")
    if receipt.get("head") != head or receipt.get("tree") != tree: raise RuntimeError("receipt identity mismatch")
    if time.time()-receipt.get("finished_at",0) > MAX_AGE: raise RuntimeError("receipt stale")
    if receipt.get("source_digest") != tree_digest(source): raise RuntimeError("receipt source digest mismatch")
    expected={"dependency_security":"PASS","ssg":"PASS","playwright":"62/62","lighthouse_mobile":"33/33","lighthouse_desktop":"33/33"}
    if receipt.get("gates") != expected: raise RuntimeError("receipt gate matrix incomplete")

    # Independent release-critical check: receipt cannot override failing source state.
    if (Path(source)/"release-ok.txt").read_text().strip() != "OK":
        raise RuntimeError("independent release validation failed")

    site=Path(source)/"site"
    if not (site/"index.html").is_file(): raise RuntimeError("site artifact missing")
    if output.exists(): shutil.rmtree(output)
    shutil.copytree(site,output)
    for p in output.rglob("*"):
        if p.is_file() and (p.name in FORBIDDEN_PUBLIC_NAMES or p.suffix == ".map"):
            raise RuntimeError(f"forbidden public artifact: {p.name}")
    return {
      "source_head":head,"source_tree":tree,"source_digest":tree_digest(source),
      "artifact_digest":tree_digest(output),
      "receipt_digest":hashlib.sha256(json.dumps(receipt,sort_keys=True).encode()).hexdigest()
    }

def deploy_admission(output, manifest, expected_head):
    if manifest["source_head"] != expected_head: raise RuntimeError("deploy source HEAD mismatch")
    if manifest["artifact_digest"] != tree_digest(output): raise RuntimeError("artifact changed after verification")
    return True

def expect_fail(label, fn):
    try: fn()
    except Exception: print("PASS negative:",label); return
    raise AssertionError("negative case unexpectedly passed: "+label)

with tempfile.TemporaryDirectory(prefix="release-controller-canary-") as d:
    src=Path(d)/"private-source"; out=Path(d)/"public-artifact"
    src.mkdir()
    run(src,"git","init","-q")
    run(src,"git","config","user.email","canary@example.invalid")
    run(src,"git","config","user.name","Release Canary")
    (src/"site").mkdir()
    (src/"site/index.html").write_text("<!doctype html><title>canary</title>\n")
    (src/"release-ok.txt").write_text("FAIL\n")
    run(src,"git","add","."); run(src,"git","commit","-qm","fixture")
    head, tree=git_identity(src)
    receipt=make_receipt(src)

    manifest=independent_release_verify(src,receipt,head,tree,out)
    assert deploy_admission(out,manifest,head)
    print("PASS happy path")

    bad=dict(receipt); bad["head"]="0"*40
    expect_fail("wrong receipt HEAD",lambda:independent_release_verify(src,bad,head,tree,out))
    bad=dict(receipt); bad["tree"]="0"*40
    expect_fail("wrong receipt tree",lambda:independent_release_verify(src,bad,head,tree,out))
    bad=make_receipt(src,age=MAX_AGE+1)
    expect_fail("stale receipt",lambda:independent_release_verify(src,bad,head,tree,out))
    bad=make_receipt(src,status="FAIL")
    expect_fail("failed cloud CI",lambda:independent_release_verify(src,bad,head,tree,out))
    bad=dict(receipt); bad["gates"]=dict(receipt["gates"]); bad["gates"]["lighthouse_desktop"]="UNKNOWN"
    expect_fail("partial evidence",lambda:independent_release_verify(src,bad,head,tree,out))

    # A forged PASS on a new exact commit still cannot overrule the independent verifier.
    (src/"release-ok.txt").write_text("FAIL\n")
    run(src,"git","add","."); run(src,"git","commit","-qm","bad candidate")
    bad_head,bad_tree=git_identity(src); forged=make_receipt(src)
    expect_fail("forged PASS cannot override independent release check",lambda:independent_release_verify(src,forged,bad_head,bad_tree,out))

    # Restore good candidate; prove artifact tamper is caught after verification.
    (src/"release-ok.txt").write_text("OK\n")
    run(src,"git","add","."); run(src,"git","commit","-qm","good candidate")
    head,tree=git_identity(src); receipt=make_receipt(src)
    manifest=independent_release_verify(src,receipt,head,tree,out)
    (out/"index.html").write_text("tampered\n")
    expect_fail("post-verification artifact tamper",lambda:deploy_admission(out,manifest,head))

    # Prove accidental private/config leakage is rejected.
    (src/"site/.env").write_text("NOT_A_REAL_SECRET=canary\n")
    run(src,"git","add","."); run(src,"git","commit","-qm","leaky artifact")
    head,tree=git_identity(src); receipt=make_receipt(src)
    expect_fail("forbidden public artifact",lambda:independent_release_verify(src,receipt,head,tree,out))

print("PASS: release-controller architecture canary")
