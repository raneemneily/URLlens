# URLens

Explainable phishing URL analysis, running entirely in your browser.

Paste a link and URLens gives a risk score from 0 to 100, plus the reason behind every warning sign. Nothing is sent to a server and the link is never visited.

## Live demo

After enabling GitHub Pages: `https://<your-username>.github.io/urlens/`

## What it checks

- Brand typosquats (`paypa1`, `micr0soft`) using edit distance and leetspeak normalization
- Brand names in the wrong place (`paypal.secure-login.xyz`)
- Punycode / lookalike hosts (`xn--`)
- `@` tricks that hide the real host
- IP address as host
- Cheap TLDs, too many subdomains, hyphen-heavy hosts, very long URLs
- Missing HTTPS and credential keywords (`login`, `verify`, `update`...)

## Run it

No build step. Open `index.html` in a browser.

## Limits

This is a heuristic prototype. It reads the text of a URL only, so it can miss phishing on a compromised legitimate site and can flag harmless but unusual links.

## Next steps

- Evaluate precision and recall on PhishTank / OpenPhish data
- Replace hand-set weights with a small logistic regression, keeping the explanations
- Add broader homoglyph detection and a Tunisian brand list
- Package as a browser extension

## Author

[Your name] – candidature project for Securinets R&D
