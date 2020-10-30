#!/usr/bin/env python3

import sentry_sdk

import src.server


sentry_sdk.init(
    "https://2209822da78d4b4182baeefa8c854b9b@o468780.ingest.sentry.io/5497329",
    traces_sample_rate=1.0)

src.server.main()
