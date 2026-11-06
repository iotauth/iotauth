#!/usr/bin/env python3
"""System overhead benchmark runner: robot (requester) and locker on two
Raspberry Pis, Auth on a third host, driven from this machine over SSH.

Each trial is a fresh robot and locker process (new SST context, new
authorization request, new peer session) running one RETRIEVE_ITEM /
LOCKER_OPEN with --benchmark. Latencies come only from the endpoints' own
CLOCK_MONOTONIC records (robot.json / locker.json); nothing here (SSH,
process start, log copies) is part of any measured interval.

Subcommands (see README.md):
  init     create an experiment directory, settings and manifest
  prepare  check sources on the hosts, build, record versions
  run      run one block of one setting: regenerate the Auth DB for it,
           start Auth (and the Wi-Fi link / Bluetooth), run its trials,
           collect each trial, stop what it started
  resume   finish the not-yet-run trials of an interrupted block
  cleanup  stop anything this experiment started
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
EXAMPLES = os.path.join(REPO, "examples")
ENTITY_C = os.path.join(REPO, "entity", "c")
ARTIFACTS = os.path.join(REPO, "artifacts", "system_overhead")
PP_DIR = "entity/c/examples/physical_presence"
WIFI_LINK = "entity/c/wifi_com/wifi_link.sh"
BENCH_REMOTE = "/tmp/sysoh"  # per-trial scratch on the Pis
PASSWORD = "testpassword"
# Config filenames the robot/locker run with. Overridable so a relay campaign
# can point the robot at a remote locker (e.g. robot_pi42_ble_relay.config ->
# pi45) and run the locker from locker_pi45.config, without touching the graph.
ROBOT_CFG = os.environ.get("BENCH_ROBOT_CFG", "robot_pi42.config")
LOCKER_CFG = os.environ.get("BENCH_LOCKER_CFG", "locker_pi43.config")
# The Auth graph registers locker1's address; the robot resolves its peer target
# from Auth (not from its own config), so a relay to a remote locker also needs a
# graph whose locker1 host is that remote Pi (e.g. physical_presence_remote_pi44
# -> pi45). Overridable for that case.
GRAPH = os.environ.get("BENCH_GRAPH", "configs/physical_presence_remote.graph")
# Wi-Fi relay campaign only: extra env prepended to the Auth JVM (pins fixed
# measurement Wi-Fi creds so a pre-standing relay AP matches) and to the robot
# endpoint (WIFI_BSSID to force joining the relay-B AP). Empty in normal runs.
AUTH_ENV = os.environ.get("BENCH_AUTH_ENV", "")
ROBOT_WIFI_ENV = os.environ.get("BENCH_ROBOT_WIFI_ENV", "")
# Relay campaign: keep a pre-standing locker (pi45) measurement AP so the relay
# station (pi44) stays associated; skip the harness's locker-side Wi-Fi teardown
# and tell the locker to reuse the AP. Empty in normal runs.
LOCKER_WIFI_PERSIST = os.environ.get("BENCH_LOCKER_WIFI_PERSIST", "")

# The verification taxonomy (Section 7.3, V2). Each physical requirement is a
# catalog check with a topology; a method carries its resource requirements and
# default parameters. One method is selected per requirement in a config.
METHOD_DEFS = {
    # requirement, topology, method -> (requirements, default parameters)
    ("PROXIMITY", "IR"): (
        dict(requester=dict(sensors=["IR"], actuators=["IR"]),
             target=dict(sensors=["IR"], actuators=["IR"])),
        dict(rounds=128, max_delay_us=1300, success_threshold=0.8)),
    ("PROXIMITY", "LIFI"): (
        dict(requester=dict(sensors=["LiFi"], actuators=["LiFi"]),
             target=dict(sensors=["LiFi"], actuators=["LiFi"])),
        dict(rounds=128, max_delay_us=2000, success_threshold=0.8)),
    ("PROXIMITY", "ULTRASOUND"): (
        dict(requester=dict(sensors=["UltraSound"], actuators=["UltraSound"]),
             target=dict(sensors=["UltraSound"], actuators=["UltraSound"])),
        dict(max_response_us=2500000, response_timeout_ms=5000)),
    ("PROXIMITY", "BLE_RSSI"): (
        dict(requester=dict(sensors=["BLE"], actuators=["BLE"]),
             target=dict(sensors=["BLE"], actuators=["BLE"])),
        dict(min_rssi_dbm=-60, samples=20, timeout_ms=10000)),
    ("PROXIMITY", "WIFI_RSSI"): (
        dict(requester=dict(sensors=["WiFi"], actuators=["WiFi"]),
             target=dict(sensors=["WiFi"], actuators=["WiFi"])),
        dict(min_rssi_dbm=-60, samples=20, interval_ms=100)),
    ("PROXIMITY", "UWB"): (
        dict(requester=dict(sensors=["UWB"], actuators=["UWB"]),
             target=dict(sensors=["UWB"], actuators=["UWB"])),
        dict(max_distance_cm=150, samples=20, timeout_ms=10000)),
    ("POSITION_IN_REGION", "UWB_POSITION"): (
        dict(requester=dict(sensors=["UWB"], actuators=["UWB"]),
             target=dict(sensors=["UWB"], actuators=["UWB"])),
        dict(anchors=[dict(x_cm=0, y_cm=0), dict(x_cm=84, y_cm=-89),
                      dict(x_cm=84, y_cm=97)],
             expected=dict(x_cm=107, y_cm=41), tolerance_cm=50, samples=15,
             timeout_ms=8000)),
    ("SHARED_ACOUSTIC_ENVIRONMENT", "AMBIENT_AUDIO"): (
        dict(requester=dict(sensors=["Microphone"]),
             target=dict(sensors=["Microphone"])),
        dict(recording_ms=3000, similarity_threshold_milli=300, max_lag_ms=150,
             min_power_dbfs=-55)),
    # Requester scans with its camera; the locker only displays (no Auth-
    # registered capability needed on the target, so the match stays feasible).
    ("PROXIMITY", "QR"): (
        dict(requester=dict(sensors=["CAMERA"])),
        dict(timeout_ms=20000)),
    ("HUMAN_PRESENCE", "CAMERA_PERSON"): (
        dict(requester=dict(sensors=["CAMERA"])),
        dict(min_confidence="0.5")),
    ("TEMPERATURE_CHECK", "THERMOMETER"): (
        dict(target=dict(sensors=["THERMOMETER"])),
        dict(min_temperature_celsius=18)),
    ("HUMIDITY_CHECK", "HUMIDITY"): (
        dict(target=dict(sensors=["Humidity"])),
        dict(min_humidity=30)),
}
TOPOLOGY = {"PROXIMITY": "MUTUAL", "POSITION_IN_REGION": "ANCHORED",
            "SHARED_ACOUSTIC_ENVIRONMENT": "MUTUAL", "HUMAN_PRESENCE": "LOCAL",
            "TEMPERATURE_CHECK": "LOCAL", "HUMIDITY_CHECK": "LOCAL"}
# The single-device checks every config includes (Section 7.3 S0): the robot's
# camera human-absence and the locker's temperature and humidity.
REQUESTER_LOCAL = ["HUMAN_PRESENCE"]
TARGET_LOCAL = ["TEMPERATURE_CHECK", "HUMIDITY_CHECK"]
LOCAL_METHOD = {"HUMAN_PRESENCE": "CAMERA_PERSON",
                "TEMPERATURE_CHECK": "THERMOMETER", "HUMIDITY_CHECK": "HUMIDITY"}
ACOUSTIC_ARGS = ("--mic plughw:CARD=MICROPHONE,DEV=0 "
                 "--spk plughw:CARD=Device,DEV=0")
# Wi-Fi RSSI/timing measures over a direct wlan1 link the endpoints bring up
# themselves from Auth-provisioned credentials: the locker opens the AP
# (192.168.77.1), the robot joins as STA. Both sides need the link script
# (path relative to the build/ cwd). Requires hostapd (AP side) +
# wpa_supplicant and a USB Wi-Fi dongle (wlan1) on each.
WIFI_LINK_FLAG = "--wifi-link-script ../../../wifi_com/wifi_link.sh"
HUMAN_PRESENCE_CMD = ("HUMAN_PRESENCE_CMD='python3 -m human_presence' "
                      "PYTHONPATH=%s/entity/python")  # %s = remote repo
FRESHNESS_MS = 60000

# Experiment configs. Every config also runs the S0 single-device checks; the
# cooperative ones add one physical requirement (multi adds two). Each names the
# cooperative requirement->method, the handshake comm, endpoint require flags,
# and any device args.
CONFIGS = [
    dict(setting_id="s0", label="Single-device only (S0)", coop={}, comm="tcp",
         requires=[], sudo=False, timeout=180),
    dict(setting_id="prox_ir", label="PROXIMITY / IR",
         coop={"PROXIMITY": "IR"}, comm="ir", requires=["--require-ir-hk"],
         sudo=True, timeout=300),
    dict(setting_id="prox_lifi", label="PROXIMITY / LiFi",
         coop={"PROXIMITY": "LIFI"}, comm="lifi",
         requires=["--require-lifi-hk"], sudo=True, timeout=300,
         # Per-Pi LiFi GPIO wiring (robot pi42: TX23/RX22; locker pi43 reversed).
         # Overridable per host pair (e.g. pi44/pi45) via env.
         robot_args=os.environ.get("BENCH_ROBOT_LIFI_ARGS",
                                   "--lifi-tx-gpio 23 --lifi-rx-gpio 22"),
         locker_args=os.environ.get("BENCH_LOCKER_LIFI_ARGS",
                                    "--lifi-tx-gpio 23 --lifi-rx-gpio 22")),
    dict(setting_id="prox_acoustic", label="PROXIMITY / acoustic keyed echo",
         coop={"PROXIMITY": "ULTRASOUND"}, comm="tcp",
         requires=["--require-ultrasound-echo"], sudo=False, timeout=180,
         robot_args=ACOUSTIC_ARGS, locker_args=ACOUSTIC_ARGS),
    dict(setting_id="prox_ble_timing",
         label="PROXIMITY / BLE RSSI + authenticated timing",
         coop={"PROXIMITY": "BLE_RSSI"}, comm="bluetooth",
         requires=["--require-ble-rssi"], sudo=True, timeout=180,
         robot_args="--ble-timing-mode measure --ble-timing-rounds 20",
         locker_args="--ble-timing-mode measure --ble-timing-rounds 20"),
    dict(setting_id="prox_wifi_timing",
         label="PROXIMITY / Wi-Fi RSSI + authenticated timing",
         coop={"PROXIMITY": "WIFI_RSSI"}, comm="tcp",
         requires=["--require-wifi-rssi", "--wifi-timing-mode measure"], sudo=False,
         timeout=180, robot_args="--wifi-peer 192.168.77.1 " + WIFI_LINK_FLAG,
         locker_args=WIFI_LINK_FLAG),
    dict(setting_id="prox_uwb", label="PROXIMITY / UWB ranging",
         coop={"PROXIMITY": "UWB"}, comm="tcp", requires=["--require-uwb"],
         sudo=False, timeout=180, robot_args="--uwb-dev /dev/ttyACM0",
         locker_args="--uwb-dev /dev/ttyACM0"),
    dict(setting_id="position_uwb", label="POSITION_IN_REGION / UWB positioning",
         coop={"POSITION_IN_REGION": "UWB_POSITION"}, comm="tcp",
         requires=["--require-uwb-position"], sudo=False, timeout=180,
         robot_args="--uwb-dev /dev/ttyACM0",
         locker_args="--uwb-anchor-dev /dev/ttyACM0 --uwb-anchor-dev "
                     "/dev/ttyACM1 --uwb-anchor-dev /dev/ttyACM2"),
    dict(setting_id="ambient_audio",
         label="SHARED_ACOUSTIC_ENVIRONMENT / ambient audio",
         coop={"SHARED_ACOUSTIC_ENVIRONMENT": "AMBIENT_AUDIO"}, comm="tcp",
         requires=["--require-ambient-audio"], sudo=False, timeout=180,
         robot_args=ACOUSTIC_ARGS, locker_args=ACOUSTIC_ARGS),
    # QR-code exchange: a session-bound challenge shown on the locker's
    # framebuffer and read by the robot's camera. Separate relay experiment (no
    # timing deadline); the locker displays its id for discovery (--show-qr).
    dict(setting_id="prox_qr", label="PROXIMITY / QR-code exchange",
         coop={"PROXIMITY": "QR"}, comm="tcp", requires=["--require-qr"],
         sudo=False, timeout=300, locker_args="--show-qr"),
]


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


def read_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def log_command(exp_dir):
    with open(os.path.join(exp_dir, "commands.log"), "a") as f:
        f.write("%s  %s\n" % (now_utc(), " ".join(
            shlex.quote(a) for a in sys.argv)))


# ---------------------------------------------------------------- SSH

class Hosts:
    def __init__(self, cfg):
        self.auth = cfg["auth_host"]
        self.robot = cfg["robot_host"]
        self.locker = cfg["locker_host"]
        self.repo = cfg["remote_repo"]


def ssh(host, cmd, timeout=60, check=False):
    """Runs `cmd` on `host`. @return (exit code, stdout, stderr); code 255
    is an SSH failure, None a local timeout."""
    try:
        p = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
             cmd], stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout)
    except subprocess.TimeoutExpired:
        if check:
            raise RuntimeError("timeout on %s: %s" % (host, cmd))
        return None, "", "local timeout"
    if check and p.returncode != 0:
        raise RuntimeError("%s: %s failed (%s): %s" % (
            host, cmd, p.returncode, p.stderr.strip()[-500:]))
    return p.returncode, p.stdout, p.stderr


def scp(src, dst, timeout=60):
    try:
        p = subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-o",
                            "ConnectTimeout=10", src, dst],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        return False


# ----------------------------------------------------------- settings

HANDSHAKE_METHODS = {
    "tcp": [dict(id="TCP", requirements={}, parameters={})],
    "wifi": [dict(id="WIFI", requirements=dict(
        requester=dict(sensors=["WiFi"], actuators=["WiFi"]),
        target=dict(sensors=["WiFi"], actuators=["WiFi"])),
        parameters=dict(host="192.168.77.1", port="21100")),
        dict(id="TCP", requirements={}, parameters={})],
    "bluetooth": [dict(id="TCP", requirements={}, parameters={}),
                  dict(id="BLE", requirements=dict(
                      requester=dict(sensors=["BLE"], actuators=["BLE"]),
                      target=dict(sensors=["BLE"], actuators=["BLE"])),
                      parameters={})],
    "ir": [dict(id="TCP", requirements={}, parameters={}),
           dict(id="IR", requirements=dict(
               requester=dict(sensors=["IR"], actuators=["IR"]),
               target=dict(sensors=["IR"], actuators=["IR"])),
               parameters={})],
    "lifi": [dict(id="TCP", requirements={}, parameters={}),
             dict(id="LIFI", requirements=dict(
                 requester=dict(sensors=["LiFi"], actuators=["LiFi"]),
                 target=dict(sensors=["LiFi"], actuators=["LiFi"])),
                 parameters={})],
}


def config_checks(config):
    """(check, method) pairs this config needs: its cooperative requirement(s)
    plus the single-device checks every config includes (S0)."""
    pairs = [(c, m) for c, m in config["coop"].items()]
    pairs += [(c, LOCAL_METHOD[c]) for c in TARGET_LOCAL + REQUESTER_LOCAL]
    return pairs


def check_entry(check, method):
    reqs, params = METHOD_DEFS[(check, method)]
    return dict(id=check, topology=TOPOLOGY[check],
                methods=[dict(id=method, requirements=reqs,
                              parameters=dict(params))])


def config_catalog(config):
    """A catalog with exactly this config's checks, each restricted to its one
    selected method, so Auth's selection is deterministic."""
    catalog = dict(checks=[check_entry(c, m) for c, m in config_checks(config)])
    catalog["checks"].append(dict(id="HANDSHAKE_TRANSPORT", topology="MUTUAL",
                                  methods=HANDSHAKE_METHODS[config["comm"]]))
    return catalog


def config_policy(config):
    """The RETRIEVE_ITEM / GRIP_ITEM policy for this config: its cooperative
    requirements, plus the target-local and requester-local single-device
    checks, each with a freshness bound."""
    coop = list(config["coop"].keys())
    fresh = {c: FRESHNESS_MS for c in coop + TARGET_LOCAL + REQUESTER_LOCAL}
    base = dict(RequestingGroup="Robots", TargetType="Action",
                MaxNumSessionKeyOwners=2,
                SessionCryptoSpec="AES-128-CBC:SHA256",
                AbsoluteValidity="1*day", RelativeValidity="2*hour",
                Expiration="Infinity", IsDelegated=0)
    retrieve = dict(base, Target="RETRIEVE_ITEM", Challenges=dict(
        PhysicalPresenceRequirements=coop, TargetLocalChecks=TARGET_LOCAL,
        RequesterLocalChecks=REQUESTER_LOCAL, PhysicalPresenceFreshnessMs=fresh))
    grip = dict(base, Target="GRIP_ITEM", Challenges=dict(
        PhysicalPresenceRequirements=[], PhysicalPresenceFreshnessMs={}))
    return [retrieve, grip]


def build_settings():
    settings, order = {}, []
    for config in CONFIGS:
        sid = config["setting_id"]
        resolved = {c: dict(method=m, topology=TOPOLOGY[c],
                            parameters=dict(METHOD_DEFS[(c, m)][1]))
                    for c, m in config_checks(config)}
        settings[sid] = dict(
            setting_id=sid, label=config["label"],
            cooperative=config["coop"],
            requirements=list(config["coop"].keys()),
            target_local=list(TARGET_LOCAL), requester_local=list(REQUESTER_LOCAL),
            handshake_transport=config["comm"], comm=config["comm"],
            requires=list(config["requires"]), sudo=config["sudo"],
            timeout=config["timeout"], robot_args=config.get("robot_args", ""),
            locker_args=config.get("locker_args", ""),
            resolved_methods=resolved, freshness_bound_ms=FRESHNESS_MS)
        order.append(sid)
    return settings, order


# ------------------------------------------------------------ git info

def git(*args, cwd=REPO):
    return subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True,
                          text=True).stdout.strip()


SOURCE_EXT = (".c", ".h", ".java", ".js", ".json", ".sh", ".py", ".txt",
              ".config")


def dirty_hashes():
    out = {}
    for root, label in ((REPO, ""), (ENTITY_C, "entity/c/")):
        for line in git("status", "--porcelain", cwd=root).splitlines():
            path = line[3:].strip()
            full = os.path.join(root, path)
            if path.startswith("artifacts") or not os.path.isfile(full):
                continue
            if path.endswith(SOURCE_EXT):
                out[label + path] = sha256_file(full)
    return out


# Sources the endpoints are built from; prepare checks they match here.
CHECKED_SOURCES = [
    "entity/c/examples/physical_presence/robot.c",
    "entity/c/examples/physical_presence/locker.c",
    "entity/c/examples/physical_presence/hk_check.h",
    "entity/c/examples/physical_presence/physical_options.h",
    "entity/c/examples/physical_presence/benchmark.h",
    "entity/c/physical_com/freshness.c",
    "entity/c/physical_com/hk.c",
    "entity/c/bluetooth_com/ble_adv_rssi.c",
    "entity/c/bluetooth_com/bt_adv_radio.c",
    "entity/c/wifi_com/wifi_rssi.c",
    "entity/c/uwb_com/uwb_range.c",
    "entity/c/ultrasonic_com/ultrasonic_echo.c",
    "entity/c/src/c_api.c",
]


# ------------------------------------------------------------ commands

def exp_paths(args):
    exp_dir = os.path.join(ARTIFACTS, args.experiment)
    if not os.path.isdir(exp_dir):
        raise SystemExit("no experiment %s (run init first)" % exp_dir)
    return exp_dir


def cmd_init(args):
    exp_id = args.experiment or datetime.datetime.now().strftime(
        "sysoh-%Y%m%d-%H%M%S")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", exp_id):
        raise SystemExit("experiment id: letters, digits, . _ - only")
    exp_dir = os.path.join(ARTIFACTS, exp_id)
    if os.path.exists(exp_dir):
        raise SystemExit("%s exists; never overwritten" % exp_dir)
    settings, order = build_settings()  # fails before creating files
    by_id = {c["setting_id"]: c for c in CONFIGS}
    os.makedirs(os.path.join(exp_dir, "trials"))
    os.makedirs(os.path.join(exp_dir, "auth_logs"))
    os.makedirs(os.path.join(exp_dir, "config"))
    for sid in order:
        write_json(os.path.join(exp_dir, "config", "catalog_%s.json" % sid),
                   config_catalog(by_id[sid]))
        write_json(os.path.join(exp_dir, "config", "policy_%s.json" % sid),
                   config_policy(by_id[sid]))
    write_json(os.path.join(exp_dir, "settings.json"),
               dict(order=order, settings=settings))
    placement = read_json(args.placement) if args.placement else None
    cfg = dict(auth_host=args.auth_host, robot_host=args.robot_host,
               locker_host=args.locker_host, remote_repo=args.remote_repo)
    write_json(os.path.join(exp_dir, "hosts.json"), cfg)
    pp = os.path.join(REPO, PP_DIR)
    manifest = dict(
        experiment_id=exp_id, created_at_utc=now_utc(),
        repository_commit=git("rev-parse", "HEAD"),
        entity_c_commit=git("rev-parse", "HEAD", cwd=ENTITY_C),
        dirty_source_hashes=dirty_hashes(),
        binary_hashes=None, build_flags=None,  # filled by prepare
        hosts=dict(auth=cfg["auth_host"], requester=cfg["robot_host"],
                   locker=cfg["locker_host"]),
        hardware=None, software=None,  # filled by prepare
        auth_network="Endpoints reach Auth over TCP at the Auth address in "
                     "robot_pi42.config / locker_pi43.config.",
        peer_transport={sid: settings[sid]["handshake_transport"]
                        for sid in order},
        placement=placement.get("placement") if placement else
        "NOT RECORDED: fill in placement.json and pass --placement",
        environment=placement.get("environment") if placement else
        "NOT RECORDED",
        policy_hash={sid: sha256_file(os.path.join(
            exp_dir, "config", "policy_%s.json" % sid)) for sid in order},
        catalog_hash={sid: sha256_file(os.path.join(
            exp_dir, "config", "catalog_%s.json" % sid)) for sid in order},
        config_hashes={n: sha256_file(os.path.join(pp, n)) for n in
                       (ROBOT_CFG, LOCKER_CFG)},
        settings=order,
        key_state_policy=dict(
            per_trial="new robot and locker process, new SST context "
                      "(init_SST), new RETRIEVE_ITEM authorization request, "
                      "new peer session; nothing reused across trials",
            auth="one Auth process per block, kept running across the "
                 "block's trials; Auth DB regenerated between blocks only",
            distribution_key="per the endpoint configs; each endpoint "
                             "records dist_key_loaded_at_init and "
                             "perm_dist_key_mode in its result",
            warmup_note="warmup trials absorb Auth/JVM and device start-up; "
                        "they do not remove a new process's first-request "
                        "key handling, which every trial includes"),
        logging_mode="default SST logging, stdout/stderr line-buffered to a "
                     "file on each Pi; no per-sample logs in timed loops",
        attempt_policy=dict(
            warmup=5, measured=100, pilot=10,
            rule="fixed attempt count per block; failed attempts are kept "
                 "and never replaced; an extra block, if any, is a separate "
                 "fixed-size block"),
        percentile_method="numpy.percentile(..., method='linear')",
        experimental_delays=dict(action_test_delay_ms=0,
                                 ultrasound_echo_test_delay_ms=0),
        local_verification="every config runs the single-device S0 checks: the "
                           "robot's camera HUMAN_PRESENCE (requester-local) and "
                           "the locker's TEMPERATURE_CHECK and HUMIDITY_CHECK "
                           "(target-local); each is timed per check.",
        taxonomy=dict(
            cooperative=["PROXIMITY", "POSITION_IN_REGION",
                         "SHARED_ACOUSTIC_ENVIRONMENT"],
            single_device=TARGET_LOCAL + REQUESTER_LOCAL,
            note="different requirements are verified and recorded "
                 "independently; never substituted for one another"),
    )
    write_json(os.path.join(exp_dir, "manifest.json"), manifest)
    write_json(os.path.join(exp_dir, "schedule.json"), dict(blocks=[]))
    log_command(exp_dir)
    print(exp_dir)


def remote_sources_match(hosts):
    local = {p: sha256_file(os.path.join(REPO, p)) for p in CHECKED_SOURCES}
    bad = {}
    for host in (hosts.robot, hosts.locker):
        cmd = "cd %s && sha256sum %s" % (hosts.repo, " ".join(CHECKED_SOURCES))
        rc, out, err = ssh(host, cmd, timeout=30)
        remote = {}
        for line in out.splitlines():
            h, p = line.split(None, 1)
            remote[p.strip()] = h
        diff = [p for p in CHECKED_SOURCES if remote.get(p) != local[p]]
        if rc != 0 or diff:
            bad[host] = diff or ["(cannot read: %s)" % err.strip()[-200:]]
    return local, bad


def cmd_prepare(args):
    exp_dir = exp_paths(args)
    hosts = Hosts(read_json(os.path.join(exp_dir, "hosts.json")))
    log_command(exp_dir)
    if args.sync:
        for host in (hosts.robot, hosts.locker):
            subprocess.run(["rsync", "-rlc", "--exclude", "build",
                            "--exclude", ".git", "-e", "ssh -o BatchMode=yes",
                            ENTITY_C + "/", "%s:%s/entity/c/" % (
                                host, hosts.repo)], check=True)
        for sub in ("auth", "examples/policies",
                    "examples/physical_context_challenges"):
            subprocess.run(["rsync", "-rlc", "--exclude", "target",
                            "--exclude", ".git", "-e", "ssh -o BatchMode=yes",
                            os.path.join(REPO, sub) + "/",
                            "%s:%s/%s/" % (hosts.auth, hosts.repo, sub)],
                           check=True)
    local, bad = remote_sources_match(hosts)
    if bad:
        raise SystemExit("sources differ from this checkout (use --sync): %s"
                         % json.dumps(bad, indent=1))
    build = ("sudo apt-get install -y -q libasound2-dev libbluetooth-dev "
             "> /dev/null && cd %s/%s && rm -rf build && mkdir build && "
             "cd build && cmake .. > /dev/null && make -j4 2>&1 | "
             "grep -E 'warning|error' ; test -x robot && test -x locker"
             % (hosts.repo, PP_DIR))
    info_cmd = (
        "cd %s/%s/build && echo BIN && sha256sum robot locker && echo FLAGS "
        "&& grep -E '^CMAKE_(BUILD_TYPE|C_FLAGS|C_COMPILER):' CMakeCache.txt "
        "; grep -E 'HAVE_[A-Z]+_TRANSPORT' -o CMakeFiles/robot.dir/flags.make "
        "| sort -u ; echo SW && uname -r && . /etc/os-release && echo "
        "$PRETTY_NAME && gcc --version | head -1 && (bluetoothctl --version "
        "|| true) && echo HW && tr -d '\\0' < /proc/device-tree/model && echo "
        "&& ls /dev/serial/by-id/ 2>/dev/null; /usr/sbin/iw dev 2>/dev/null | grep -E "
        "'Interface|type'; arecord -l 2>/dev/null | grep card; aplay -l "
        "2>/dev/null | grep card; hciconfig hci0 2>/dev/null | grep 'BD "
        "Address'" % (hosts.repo, PP_DIR))
    manifest = read_json(os.path.join(exp_dir, "manifest.json"))
    manifest["binary_hashes"], manifest["build_flags"] = {}, {}
    manifest["hardware"], manifest["software"] = {}, {}
    for role, host in (("requester", hosts.robot), ("locker", hosts.locker)):
        print("building on", host)
        rc, out, err = ssh(host, build, timeout=900)
        if rc != 0:
            raise SystemExit("build failed on %s:\n%s%s" % (host, out, err))
        rc, out, err = ssh(host, info_cmd, timeout=60)
        sections = dict(BIN=[], FLAGS=[], SW=[], HW=[])
        cur = None
        for line in out.splitlines():
            if line in sections:
                cur = line
            elif cur:
                sections[cur].append(line)
        manifest["binary_hashes"][role] = sections["BIN"]
        manifest["build_flags"][role] = sections["FLAGS"]
        manifest["software"][role] = sections["SW"]
        manifest["hardware"][role] = sections["HW"]
    rc, out, err = ssh(hosts.auth, "export PATH=/opt/maven/bin:$HOME/.sdkman/"
                       "candidates/maven/current/bin:$PATH && cd %s/auth && "
                       "mvn -q -DskipTests package "
                       "&& java -version 2>&1 | head -1" % hosts.repo,
                       timeout=900)
    if rc != 0:
        raise SystemExit("Auth build failed:\n%s%s" % (out, err))
    manifest["software"]["auth"] = out.strip().splitlines()[-1:]
    manifest["checked_sources"] = local
    manifest["prepared_at_utc"] = now_utc()
    write_json(os.path.join(exp_dir, "manifest.json"), manifest)
    print("prepared; versions recorded in manifest.json")


# --------------------------------------------------------- a block run

class Block:
    def __init__(self, exp_dir, hosts, setting, block):
        self.exp_dir, self.hosts, self.setting = exp_dir, hosts, setting
        self.block = block
        self.comm = setting["comm"]
        self.sudo = setting["sudo"]
        self.timeout = setting["timeout"]
        self.requires = setting["requires"]
        self.auth_pid_file = "/tmp/sysoh_auth.%s.%s.pid" % (
            os.path.basename(exp_dir), block["block_id"])
        self.auth_log = self.auth_pid_file.replace(".pid", ".log")
        self.bt_peer = None
        self.started = []

    def remote_dir(self, run_id):
        return "%s/%s/%s" % (BENCH_REMOTE, os.path.basename(self.exp_dir),
                             run_id)

    # -- start: Auth DB for this setting, Auth, links
    def start(self):
        h = self.hosts
        exp = os.path.basename(self.exp_dir)
        sid = self.setting["setting_id"]
        rdir = "/tmp/sysoh_cfg_%s" % exp
        ssh(h.auth, "mkdir -p %s" % rdir, check=True)
        for local, remote in (("policy_%s.json" % sid, "policy.json"),
                              ("catalog_%s.json" % sid, "catalog.json")):
            if not scp(os.path.join(self.exp_dir, "config", local),
                       "%s:%s/%s" % (h.auth, rdir, remote)):
                raise RuntimeError("cannot upload %s" % local)
        ports = "ss -ltn | grep -qE ':(21900|21901)( |$)'"
        if ssh(h.auth, ports)[0] == 0:
            raise RuntimeError("Auth ports already in use on %s; not "
                               "touching it" % h.auth)
        print("[%s] regenerating Auth DB" % sid)
        # mvn (for the DB generator) is not in the non-interactive SSH PATH on
        # the Auth host; add the common install locations.
        ssh(h.auth, "export PATH=/opt/maven/bin:$HOME/.sdkman/candidates/maven/"
            "current/bin:$PATH && cd %s/examples && ./cleanAll.sh > /dev/null "
            "&& ./generateAll.sh -g %s -po "
            "%s/policy.json -ch %s/catalog.json -p %s -lc > /dev/null"
            % (h.repo, GRAPH, rdir, rdir, PASSWORD), timeout=900, check=True)
        for ent, host in (("Robot1", h.robot), ("Locker1", h.locker)):
            ssh(host, "mkdir -p %s/entity/auth_certs "
                "%s/entity/credentials/certs/net1 "
                "%s/entity/credentials/keys/net1" % ((h.repo,) * 3),
                check=True)
            for path in ("entity/auth_certs/Auth101EntityCert.pem",
                         "entity/credentials/certs/net1/Net1.%sCert.pem" % ent,
                         "entity/credentials/keys/net1/Net1.%sKey.pem" % ent):
                if not scp("%s:%s/%s" % (h.auth, h.repo, path),
                           "%s:%s/%s" % (host, h.repo, path)):
                    raise RuntimeError("cannot copy %s to %s" % (path, host))
        for name, host in ((ROBOT_CFG, h.robot),
                           (LOCKER_CFG, h.locker)):
            if not scp(os.path.join(REPO, PP_DIR, name),
                       "%s:%s/%s/%s" % (host, h.repo, PP_DIR, name)):
                raise RuntimeError("cannot deploy %s" % name)
        # Acoustic configs need the USB speaker/mic at usable levels; a fresh
        # boot can leave them low or muted, which makes the ggwave echo fail to
        # decode and the ULTRASOUND/AMBIENT_AUDIO check abort. Set them by card
        # name (swap-proof across pi42/pi43's differing card numbers).
        if "--mic" in (self.setting.get("robot_args", "") +
                       self.setting.get("locker_args", "")):
            for host in (h.robot, h.locker):
                ssh(host, "amixer -c Device sset PCM 90% >/dev/null 2>&1; "
                    "amixer -c MICROPHONE sset Mic 85% >/dev/null 2>&1; true")
        print("[%s] starting Auth" % sid)
        # Auth's command line reads stdin with BufferedReader.readLine; keep
        # that stream open but empty so it blocks forever (keeping the JVM's
        # main thread alive) without consuming data. /dev/zero floods it and
        # OOMs the readLine StringBuilder; /dev/null gives EOF, so the command
        # loop returns and (on JDK 21) the JVM exits before the entity server
        # serves. `tail -f /dev/null` never writes and never closes.
        ssh(h.auth, "cd %s/auth/auth-server && setsid nohup bash -c 'echo $$ > "
            "%s; exec %sjava -jar target/auth-server-jar-with-dependencies.jar "
            "--properties ../properties/exampleAuth101.properties -s %s "
            "< <(exec tail -f /dev/null)' > %s 2>&1 &"
            % (h.repo, self.auth_pid_file,
               ("env " + AUTH_ENV + " ") if AUTH_ENV else "",
               PASSWORD, self.auth_log), timeout=30)
        self.started.append("auth")
        for _ in range(45):
            time.sleep(2)
            if ssh(h.auth, "kill -0 $(cat %s) 2>/dev/null && ss -ltn | grep "
                   "-qE ':21900( |$)'" % self.auth_pid_file)[0] == 0:
                break
        else:
            raise RuntimeError("Auth did not come up")
        comm = self.comm
        if WIFI_LINK_FLAG in (self.setting.get("robot_args", "") +
                              self.setting.get("locker_args", "")):
            # The endpoints bring up the Auth-provisioned measurement link
            # themselves (locker=AP, robot=STA) via --wifi-link-script over a
            # TCP handshake; the harness only clears any stale link first. In the
            # relay campaign the locker AP is pre-standing, so leave it alone.
            wifi_hosts = (h.robot,) if LOCKER_WIFI_PERSIST else (h.robot, h.locker)
            for host in wifi_hosts:
                ssh(host, "%s/%s down" % (h.repo, WIFI_LINK), timeout=60)
            self.started.append("wifi")
        # BLE timing uses a separate L2CAP measurement link even when the
        # control transport is TCP, so set up Bluetooth and discover the
        # locker's BD address for --bt-peer whenever it is requested.
        ble_timing = "--ble-timing-mode" in (
            self.setting.get("robot_args", "") +
            self.setting.get("locker_args", ""))
        if comm == "bluetooth" or ble_timing:
            up = ("for r in /sys/class/rfkill/rfkill*; do if [ \"$(cat "
                  "$r/type)\" = bluetooth ]; then echo 0 | sudo tee $r/soft "
                  "> /dev/null; fi; done; bluetoothctl power on > /dev/null")
            for host in (h.robot, h.locker):
                ssh(host, up, timeout=30, check=True)
                self.clear_le_links(host)
            rc, out, _ = ssh(h.locker, "hciconfig hci0 | awk '/BD Address/ "
                             "{print $3}'", check=True)
            self.bt_peer = out.strip()

    def clear_le_links(self, host):
        # Only links between these two test Pis exist here; a leftover one
        # (bluetoothd keeps them up) breaks the next L2CAP connection.
        ssh(host, "for x in $(hcitool con | awk '/handle/ {print $5}'); do "
            "sudo hcitool ledc $x; done", timeout=30)

    # -- one trial
    def endpoint_cmd(self, role, run_id):
        h = self.hosts
        rdir = self.remote_dir(run_id)
        prog, cfg = (("robot", ROBOT_CFG) if role == "robot" else
                     ("locker", LOCKER_CFG))
        extra = self.setting.get("%s_args" % role, "")
        ble_timing = "--ble-timing-mode" in (
            self.setting.get("robot_args", "") +
            self.setting.get("locker_args", ""))
        if role == "robot" and (self.comm == "bluetooth" or ble_timing):
            extra += " --bt-peer %s" % self.bt_peer
        requires = " ".join(self.requires)
        # Every config runs the robot's camera HUMAN_PRESENCE; provide the
        # detector. $HOME is expanded by the user's shell before sudo, so the
        # path is correct even when the endpoint runs under sudo.
        # The ambient-audio compare tool (run by the locker) and the camera
        # detector (run by the robot) are both Python modules under
        # entity/python, so both endpoints need PYTHONPATH; only the robot runs
        # the camera detector. $HOME is expanded by the user's shell before sudo,
        # so the path is correct even when the endpoint runs under sudo.
        env = "PYTHONPATH=\"$HOME/%s/entity/python\" " % h.repo
        if role == "robot":
            # BENCH_HP_CMD overrides the person-detector command (e.g. a wrapper
            # that reads the pre-warmed qrstream instead of opening the camera, so
            # a persistent QR camera daemon and HUMAN_PRESENCE do not fight over
            # the single camera). Default = capture a fresh frame.
            hp = os.environ.get("BENCH_HP_CMD", "python3 -m human_presence")
            env = "HUMAN_PRESENCE_CMD='%s' " % hp + env
            if ROBOT_WIFI_ENV:  # relay campaign: pin the relay-B AP BSSID etc.
                env = ROBOT_WIFI_ENV + " " + env
        if role == "locker" and LOCKER_WIFI_PERSIST:
            env = "PHYS_WIFI_REUSE_AP=1 " + env
        prefix = "sudo env " + env if self.sudo else "env " + env
        return ("cd %s/%s/build && %sstdbuf -oL -eL ./%s ../%s --comm_type %s "
                "%s %s --benchmark --benchmark-run-id %s --benchmark-output "
                "%s/%s.json > %s/%s.log 2>&1"
                % (h.repo, PP_DIR, prefix, prog, cfg, self.comm, requires,
                   extra, run_id, rdir, role, rdir, role))

    def run_trial(self, entry):
        h = self.hosts
        run_id = entry["run_id"]
        tdir = os.path.join(self.exp_dir, "trials", run_id)
        os.makedirs(tdir, exist_ok=True)
        rdir = self.remote_dir(run_id)
        status = dict(run_id=run_id, setting_id=entry["setting_id"],
                      block_id=self.block["block_id"], phase=entry["phase"],
                      attempt_index=entry["attempt_index"],
                      started_utc=now_utc(), infrastructure_errors=[])
        errs = status["infrastructure_errors"]
        sudo = "sudo " if self.sudo else ""
        for host in (h.robot, h.locker):
            if ssh(host, "mkdir -p %s && chmod 777 %s" % (rdir, rdir))[0] != 0:
                errs.append("cannot prepare %s" % host)
        ble_timing = "--ble-timing-mode" in (
            self.setting.get("robot_args", "") +
            self.setting.get("locker_args", ""))
        if self.comm == "bluetooth" or ble_timing:
            for host in (h.robot, h.locker):
                self.clear_le_links(host)
        if "wifi" in self.started:
            # Each trial's endpoints bring up a fresh Auth-provisioned link, so
            # tear down any link (and stale hostapd/wpa_supplicant) left by the
            # previous trial first, or the AP fails to start. In the relay
            # campaign the locker AP is pre-standing and shared, so leave it up.
            wifi_hosts = (h.robot,) if LOCKER_WIFI_PERSIST else (h.robot, h.locker)
            for host in wifi_hosts:
                ssh(host, "%s/%s down >/dev/null 2>&1; sudo pkill -x hostapd "
                    "2>/dev/null; sudo pkill -x wpa_supplicant 2>/dev/null; "
                    "sleep 3; true"  # let the dongle/NetworkManager settle
                    % (h.repo, WIFI_LINK), timeout=60)
        locker_cmd = self.endpoint_cmd("locker", run_id)
        if not errs:
            ssh(h.locker, "setsid nohup sh -c %s < /dev/null > /dev/null 2>&1 &"
                % shlex.quote(locker_cmd + "; echo $? > %s/locker.exit"
                              % rdir), timeout=30)
            # Ready = listening (TCP/Wi-Fi) or advertising (Bluetooth); this
            # wait is outside every measured interval.
            ready = False
            for _ in range(40):
                time.sleep(0.5)
                rc, out, _ = ssh(h.locker, "grep -qE 'listening on port|"
                                 "advertising, waiting|listening for handshake1'"
                                 " %s/locker.log && echo "
                                 "R; test -e %s/locker.exit && echo X"
                                 % (rdir, rdir), timeout=20)
                if "R" in out.split():
                    ready = True
                    break
                if "X" in out.split():
                    break
            if not ready:
                errs.append("locker did not become ready")
        if not errs:
            timeout = self.timeout
            robot_cmd = self.endpoint_cmd("robot", run_id)
            robot_cmd = robot_cmd.replace(
                "stdbuf", "timeout %d stdbuf" % timeout, 1)
            rc, _, err = ssh(h.robot, "%s; echo $? > %s/robot.exit"
                             % (robot_cmd, rdir), timeout=timeout + 60)
            if rc is None or rc == 255:
                errs.append("robot ssh failed: %s" % err.strip()[-200:])
            # Let the locker finish its own gate and record.
            for _ in range(60):
                if ssh(h.locker, "test -e %s/locker.exit" % rdir)[0] == 0:
                    break
                time.sleep(1)
            else:
                status["locker_stopped_by_runner"] = True
        # Stop only this run's processes (matched by its unique run ID).
        for host in (h.robot, h.locker):
            ssh(host, "%spkill -f -- '[-]-benchmark-run-id %s' ; true"
                % (sudo, run_id), timeout=30)
        for role, host in (("robot", h.robot), ("locker", h.locker)):
            for name in ("%s.json" % role, "%s.log" % role,
                         "%s.exit" % role):
                rc, out, _ = ssh(host, "%scat %s/%s" % (sudo, rdir, name),
                                 timeout=60)
                if rc == 0:
                    with open(os.path.join(tdir, name), "w") as f:
                        f.write(out)
                elif rc is None or rc == 255:
                    errs.append("cannot collect %s from %s" % (name, host))
            status["%s_exit_code" % role] = None
            p = os.path.join(tdir, "%s.exit" % role)
            if os.path.exists(p):
                txt = open(p).read().strip()
                status["%s_exit_code" % role] = int(txt) if txt.isdigit() \
                    else None
        if self.comm == "bluetooth":
            for host in (h.robot, h.locker):
                self.clear_le_links(host)
        if not errs:
            for host in (h.robot, h.locker):
                ssh(host, "%srm -rf %s" % (sudo, rdir), timeout=30)
        status["finished_utc"] = now_utc()
        write_json(os.path.join(tdir, "status.json"), status)
        return status

    # -- stop what this block started
    def stop(self):
        h = self.hosts
        if "wifi" in self.started:
            for host in (h.robot, h.locker):
                ssh(host, "%s/%s down" % (h.repo, WIFI_LINK), timeout=60)
        if "auth" in self.started:
            ssh(h.auth, "test -f %s && kill $(cat %s); rm -f %s"
                % ((self.auth_pid_file,) * 3), timeout=30)
            dst = os.path.join(self.exp_dir, "auth_logs",
                               "%s.log" % self.block["block_id"])
            scp("%s:%s" % (h.auth, self.auth_log), dst, timeout=120)


def add_block(exp_dir, setting_id, phases):
    schedule = read_json(os.path.join(exp_dir, "schedule.json"))
    n = len(schedule["blocks"]) + 1
    block_id = "b%03d" % n
    runs = []
    for phase, count in phases:
        for i in range(1, count + 1):
            runs.append(dict(
                run_id="%s.%s.%s%03d" % (setting_id, block_id, phase[0], i),
                setting_id=setting_id, phase=phase, attempt_index=i))
    block = dict(block_id=block_id, setting_id=setting_id,
                 created_utc=now_utc(), phases=dict(phases), runs=runs)
    schedule["blocks"].append(block)
    # Saved before any trial runs.
    write_json(os.path.join(exp_dir, "schedule.json"), schedule)
    return block


def run_block(exp_dir, block):
    hosts = Hosts(read_json(os.path.join(exp_dir, "hosts.json")))
    settings = read_json(os.path.join(exp_dir, "settings.json"))["settings"]
    setting = settings[block["setting_id"]]
    todo = [r for r in block["runs"] if not os.path.exists(
        os.path.join(exp_dir, "trials", r["run_id"], "status.json"))]
    if not todo:
        print("block %s: all trials already run" % block["block_id"])
        return
    b = Block(exp_dir, hosts, setting, block)
    try:
        b.start()
        for r in todo:
            st = b.run_trial(r)
            print("%s robot=%s locker=%s %s" % (
                r["run_id"], st.get("robot_exit_code"),
                st.get("locker_exit_code"),
                "; ".join(st["infrastructure_errors"])))
    finally:
        b.stop()


def cmd_run(args):
    exp_dir = exp_paths(args)
    settings = read_json(os.path.join(exp_dir, "settings.json"))["settings"]
    if args.setting not in settings:
        raise SystemExit("unknown setting %s; one of %s" % (
            args.setting, ", ".join(settings)))
    phases = []
    if args.pilot:
        phases.append(("pilot", args.pilot))
    if args.warmup:
        phases.append(("warmup", args.warmup))
    if args.attempts:
        phases.append(("measured", args.attempts))
    if not phases:
        raise SystemExit("nothing to run")
    log_command(exp_dir)
    block = add_block(exp_dir, args.setting, phases)
    print("block %s: %d trials of %s" % (block["block_id"],
                                          len(block["runs"]), args.setting))
    run_block(exp_dir, block)


def cmd_resume(args):
    exp_dir = exp_paths(args)
    log_command(exp_dir)
    schedule = read_json(os.path.join(exp_dir, "schedule.json"))
    block = next((b for b in schedule["blocks"]
                  if b["block_id"] == args.block), None)
    if not block:
        raise SystemExit("no block %s" % args.block)
    run_block(exp_dir, block)


def cmd_set_freshness(args):
    """Sets every requirement's freshness bound in every per-config policy
    (between blocks only), keeping the change and its reason on record. Earlier
    runs keep the bound their own records show."""
    exp_dir = exp_paths(args)
    if not 1 <= args.ms <= 600000:
        raise SystemExit("bound must be 1..600000 ms")
    if not args.reason:
        raise SystemExit("--reason is required")
    log_command(exp_dir)
    cfg_dir = os.path.join(exp_dir, "config")
    policy_files = sorted(f for f in os.listdir(cfg_dir)
                          if f.startswith("policy_") and f.endswith(".json"))
    for pf in policy_files:
        ppath = os.path.join(cfg_dir, pf)
        policy = read_json(ppath)
        for entry in policy:
            ch = entry.get("Challenges", {})
            fresh = ch.get("PhysicalPresenceFreshnessMs", {})
            for k in list(fresh):
                fresh[k] = args.ms
        write_json(ppath, policy)
    spath = os.path.join(exp_dir, "settings.json")
    settings = read_json(spath)
    for st in settings["settings"].values():
        st["freshness_bound_ms"] = args.ms
    write_json(spath, settings)
    mpath = os.path.join(exp_dir, "manifest.json")
    manifest = read_json(mpath)
    manifest.setdefault("freshness_bound_changes", []).append(dict(
        at_utc=now_utc(), to_ms=args.ms, reason=args.reason,
        blocks_before_change=[b["block_id"] for b in read_json(
            os.path.join(exp_dir, "schedule.json"))["blocks"]]))
    manifest["policy_hash"] = {
        pf[len("policy_"):-len(".json")]: sha256_file(os.path.join(cfg_dir, pf))
        for pf in policy_files}
    write_json(mpath, manifest)
    print("freshness bound set to %d ms in %d policies" % (
        args.ms, len(policy_files)))


def cmd_cleanup(args):
    exp_dir = exp_paths(args)
    hosts = Hosts(read_json(os.path.join(exp_dir, "hosts.json")))
    exp = os.path.basename(exp_dir)
    log_command(exp_dir)
    for host in (hosts.robot, hosts.locker):
        ssh(host, "sudo pkill -f -- '[-]-benchmark-output %s/%s/' ; %s/%s "
            "down > /dev/null 2>&1; true" % (BENCH_REMOTE, exp, hosts.repo,
                                             WIFI_LINK), timeout=60)
    ssh(hosts.auth, "for f in /tmp/sysoh_auth.%s.*.pid; do test -f $f && "
        "kill $(cat $f); rm -f $f; done; true" % exp, timeout=30)
    print("stopped this experiment's endpoints, Auth and Wi-Fi link")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--experiment")
    p.add_argument("--placement", help="placement/environment JSON")
    p.add_argument("--auth-host", default=os.environ.get("SYSOH_AUTH_HOST",
                                                         "pi41@pi41"))
    p.add_argument("--robot-host", default=os.environ.get("SYSOH_ROBOT_HOST",
                                                          "pi42@pi42"))
    p.add_argument("--locker-host", default=os.environ.get(
        "SYSOH_LOCKER_HOST", "pi43@pi43"))
    p.add_argument("--remote-repo", default="project/iotauth")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("prepare")
    p.add_argument("--experiment", required=True)
    p.add_argument("--sync", action="store_true",
                   help="rsync this checkout to the hosts first")
    p.set_defaults(func=cmd_prepare)
    p = sub.add_parser("run")
    p.add_argument("--experiment", required=True)
    p.add_argument("--setting", required=True)
    p.add_argument("--pilot", type=int, default=0)
    p.add_argument("--warmup", type=int, default=0)
    p.add_argument("--attempts", type=int, default=0,
                   help="measured attempts (fixed; failures are kept)")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("resume")
    p.add_argument("--experiment", required=True)
    p.add_argument("--block", required=True)
    p.set_defaults(func=cmd_resume)
    p = sub.add_parser("set-freshness")
    p.add_argument("--experiment", required=True)
    p.add_argument("--ms", type=int, required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_set_freshness)
    p = sub.add_parser("cleanup")
    p.add_argument("--experiment", required=True)
    p.set_defaults(func=cmd_cleanup)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
