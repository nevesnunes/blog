#!/usr/bin/env python3

# References:
# - ~/code/dependencies/frida/frida-python/examples/child_gating.py
#   - https://frida.re/news/2018/04/28/frida-10-8-released/

import frida
from frida_tools.application import Reactor
import threading
import string
import sys
import ipdb

exe = sys.argv[1]
with open(sys.argv[2], "r") as f:
    script_contents = f.read()


class Application(object):
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda _: self._stop_requested.wait())

        self._device = frida.get_local_device()
        self._sessions = set()

        # self._device.on("delivered", lambda child:
        self._device.on(
            "child-added",
            lambda child: self._reactor.schedule(lambda: self._on_delivered(child)),
        )

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        argv = [exe, input_data]
        print("✔ spawn(argv={})".format(argv))
        pid = self._device.spawn(argv)
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        print("✔ attach(pid={})".format(pid))
        session = self._device.attach(pid)
        session.on(
            "detached",
            lambda reason: self._reactor.schedule(
                lambda: self._on_detached(pid, session, reason)
            ),
        )
        print("✔ enable_child_gating()")
        session.enable_child_gating()
        print("✔ create_script()")
        script = session.create_script(script_contents)
        script.on(
            "message",
            lambda message, data: self._reactor.schedule(
                lambda: self._on_message(pid, message)
            ),
        )
        print("✔ load()")
        script.load()
        print("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_delivered(self, child):
        print("* delivered: {}".format(child))
        self._instrument(child.pid)

    def _on_detached(self, pid, session, reason):
        print("* detached: pid={}, reason='{}'".format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        if "payload" not in message:
            print("* message: {}".format(message))
            return

        char_i = message["payload"][1]
        results[char_i] = message["payload"]
        print("* message: pid={}, payload={}".format(pid, message["payload"]))


flag = ["?"] * 32
for c in string.printable:
    input_data = "".join([c] * 32)
    results = [None] * 32

    app = Application()
    app.run()

    for result in results:
        if result[2] == 1:
            flag[result[1]] = chr(result[0])

print("".join(flag))
ipdb.set_trace()
# TSGCTF{y0u_kN0w_m@ny_g0od_t0015}
