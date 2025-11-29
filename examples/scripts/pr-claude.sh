#!/usr/bin/env bash

echo "Pick a random file in this repository, then write a poem about it. The title should be 'An ode to FILENAME'. YOU MUST COMMIT the peom as POEM.md, Configure 'Claude <noreply@anthropic.com>' as your git identity if needed." | claude -p --dangerously-skip-permissions