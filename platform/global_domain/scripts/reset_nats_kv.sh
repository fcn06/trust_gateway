#!/bin/bash
# Script to delete all NATS JetStream Key-Value buckets
# This will completely wipe all data and metadata for the KV stores.
# The host application will recreate these buckets on the next start.

# Get all bucket names using the correct flag --names
# We use tail to skip potential headers and grep to ensure we only get names
BUCKETS=$(nats kv ls --names 2>/dev/null)

if [ -z "$BUCKETS" ]; then
    echo "No NATS KV buckets found."
    exit 0
fi

echo "The following NATS KV buckets will be DELETED:"
echo "$BUCKETS"
echo ""

read -p "Are you sure you want to delete all KV data? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    exit 1
fi

for bucket in $BUCKETS; do
    # Skip empty lines or accidental spaces
    if [[ -z "$bucket" ]]; then continue; fi
    
    echo "🗑️  Deleting bucket: $bucket..."
    nats kv del "$bucket" --force
done

echo ""
echo "✅ All NATS KV buckets have been deleted."
echo "Restart the host application to recreate them."
