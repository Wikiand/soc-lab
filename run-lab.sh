#!/usr/bin/env bash
set -e

echo "=================================="
echo "       LOCAL SOC DETECTION LAB"
echo "=================================="
echo
echo "[1/2] Authentication event detector"
python "$HOME/soc-lab/detector.py"
echo
echo "----------------------------------"
echo "[2/2] Failed-login burst detector"
python "$HOME/soc-lab/burst_detector.py"
echo
echo "=================================="
echo "             LAB COMPLETE"
echo "=================================="
