# ClickFix Lab

Standalone HTML/JS lab for demonstrating and studying **ClickFix** social-engineering attacks — the class of lures that trick victims into copying a crafted command from a fake browser dialog and pasting it into a terminal or Run box.

> **Authorized use only.** Built for security research, red-team training, and AV/EDR detection engineering. All payloads use `[C2]` placeholders; nothing here phones home.

## What's inside

| File | Purpose |
|---|---|
| `clickfix-lab.html` | Self-contained lure page with lab control panel |
| `clickfix-lab.js` | ES module — payload definitions, `psb64`, `getPayload`, `writeClipboard` |

## Payload coverage

| Key | Technique | MITRE | LOLBin |
|---|---|---|---|
| `ps-iex` | PowerShell IEX download-cradle | T1059.001 | `powershell.exe` |
| `ps-encoded` | `-EncodedCommand` (UTF-16LE b64) | T1027 | `powershell.exe` |
| `mshta` | HTA remote execution | T1218.005 | `mshta.exe` |
| `certutil` | File fetch + decode stager | T1105 | `certutil.exe` |
| `regsvr32` | COM scriptlet AppLocker bypass | T1218.010 | `regsvr32.exe` |

## Usage

Open `clickfix-lab.html` in a browser. The lab panel at the top lets you switch payload type and target OS. The lure page below mimics common ClickFix pretexts (Cloudflare, Google, Microsoft verification flows).

Import the module in your own tooling:

```js
import { PAYLOADS, psb64, getPayload } from './clickfix-lab.js';

const cmd = getPayload({ payload: 'ps-encoded', os: 'windows' });
```

## Detection notes

Each payload entry includes `evasion` metadata describing the bypass technique — useful for writing detection rules (Sigma, YARA, EDR queries).

## License

MIT — see `LICENSE`.
