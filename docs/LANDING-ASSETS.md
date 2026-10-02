# Landing assets — 2026-10-02

The landing page follows the application palette: navy `#08111f`, slate cards,
turquoise `#42d9d0`, rounded controls and the existing MouseVPN logo.

- `deploy/landing/assets/mousevpn-logo.png`: existing logo from `linux-gui/ui/logo.png`.
- `deploy/landing/assets/connection-hero.png`: generated with the built-in ImageGen
  tool (not the CLI), 1536 × 1024, opaque navy background. Used behind the HTML
  phone illustration. The interactive product preview is illustrative, not a
  live account session.

## Final ImageGen prompt

Use case: stylized-concept. Asset type: decorative hero artwork for the existing MouseVPN landing page, matching its desktop app's dark navy and turquoise UI. Create a sophisticated premium 3D editorial illustration: a luminous translucent turquoise glass shield hovering above a compact dark ceramic platform, two smaller rounded glass connection nodes orbiting it, very fine luminous curved paths linking them. Beautiful tactile bevels, restrained cyan edge lighting, soft physically plausible reflections and atmospheric depth. Palette strictly deep ink navy #08111f, slate navy #132337, turquoise #42d9d0 and pale cool highlights. Wide landscape composition 3:2; central object cluster occupies the middle-right, generous dark breathing room around it. Background is seamless dark navy, not transparent. This is a conceptual illustration of private connectivity, not a technical diagram. No lettering, no numbers, no logos, no interface labels, no watermark, no padlock cliche, no globes, no flags, no humans. Elegant and calm rather than gaming or neon cyberpunk. High quality polished rendering.

## Deployment

Publish only `index.html`, `style.css`, `app.js`, and `assets/`. The repository's
placeholder `releases.json` must not replace the production release manifest.
Production static files before this update are saved in
`/root/relay-landing-ui-20261002/before/` on the central server.

Verified the desktop layout and 390/320px responsive widths, all preview tabs,
image loading, release links and the password-confirmation mismatch path.
