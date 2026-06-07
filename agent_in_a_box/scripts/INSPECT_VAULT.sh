#!/bin/bash
echo "🔍 Inspecting NATS 'vault' bucket..."
nats kv ls vault
echo "----------------------------------------"
echo "If the list above is empty, your NATS data is gone."
echo "If you see keys, copy one here so we can match it against the log UUID."
