# axe-core (vendored)

Version **4.14.0**, copied unmodified from the npm package
(`https://registry.npmjs.org/axe-core/-/axe-core-4.14.0.tgz`, integrity
`sha512-9WTZxEjsZ7b13TH8JPmbV2z8CHbl80/2hm3XPEG4JgNdQLK81IBRXmSxHfMAOkSqQeRxT/0dwNDz2GOm3zzpcQ==`).

Vendored rather than fetched at runtime so a check never depends on a CDN
being up, and the exact ruleset a report was produced with is pinned in git.
Used only by `checks_accessibility.py`, which injects it into the page being
checked. Licensed MPL-2.0 (see `LICENSE`); the copyright header in
`axe.min.js` must stay intact. To upgrade: replace both files from the new
npm tarball, update the version and integrity above, and re-run the
regression harness (rule changes can move baselines).
