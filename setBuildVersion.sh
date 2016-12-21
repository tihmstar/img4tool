#!/bin/bash
sed -i '.bak' "s/.*VERSION_COMMIT_COUNT.*/#define VERSION_COMMIT_COUNT \"$(git rev-list --count HEAD)\"/" ./img4tool/all_img4tool.h 2>/dev/null || sed -i "s/.*VERSION_COMMIT_COUNT.*/#define VERSION_COMMIT_COUNT \"$(git rev-list --count HEAD)\"/" ./img4tool/all_img4tool.h 2>/dev/null
sed -i '.bak' "s/.*VERSION_COMMIT_SHA.*/#define VERSION_COMMIT_SHA \"$(git rev-parse HEAD)\"/" ./img4tool/all_img4tool.h 2>/dev/null || sed -i "s/.*VERSION_COMMIT_SHA.*/#define VERSION_COMMIT_SHA \"$(git rev-parse HEAD)\"/" ./img4tool/all_img4tool.h 2>/dev/null
