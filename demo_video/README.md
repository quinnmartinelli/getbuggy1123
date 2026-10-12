# Hackathon demo video

`getbuggy-demo.mp4` (1280×720, ~1.5 min, no audio) records the real app checking
`site/` ("Sunrise Bakery"), a local demo site with planted bugs: a dead link, a
missing photo, an image without alt text, a script crash, an order form that
silently does nothing, a banner too wide for a phone, and low-contrast text.

To re-record (from the repo root, three terminals or background jobs):

```
./venv/bin/python demo_video/serve_demo.py                                       # demo site on :8765
GETBUGGY_ALLOW_PRIVATE_CRAWL_TARGETS=true RATE_LIMIT_PER_IP_PER_HOUR=100 \
  ./venv/bin/python demo_video/demo_server.py                                    # GetBuggy on :8010
FFMPEG=/path/to/ffmpeg-with-libx264 ./venv/bin/python demo_video/record_demo.py  # writes the mp4
```

`demo_server.py` runs the unchanged app but lets the API's SSRF guard accept
`127.0.0.1:8765` only. Local tooling only; never deploy it. The wait while
the crawl runs is sped up 4× and labelled on screen; everything else is real time.
