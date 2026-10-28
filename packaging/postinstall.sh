#!/bin/sh
systemctl daemon-reload
systemctl enable --now cis-agent.timer
