#!/bin/bash
source /opt/haxhq.com/venv/bin/activate
cd /opt/haxhq.com/haxhq/haxhq
/opt/haxhq.com/venv/bin/python haxhqcli.py $@
