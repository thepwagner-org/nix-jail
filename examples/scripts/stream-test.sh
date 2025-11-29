#!/usr/bin/env bash
# Test script for multi-client streaming
# Use this to verify multiple clients can connect to the same running job

echo "Starting stream test - will run for 60 seconds"
echo "Each line shows: [iteration] random_number timestamp"
echo "---"

for i in {1..6}; do
    # Generate random number between 1000-9999
    RANDOM_NUM=$((1000 + RANDOM % 9000))

    # Print with iteration, random number, and timestamp
    echo "[$i/6] Random: $RANDOM_NUM ($(date +%H:%M:%S))"

    sleep 10
done

echo "---"
echo "Stream test complete!"
