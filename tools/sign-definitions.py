#!/usr/bin/env python3
"""
Assina e publica o Radar de Ameaças (definitions.json) com a CHAVE DO RADAR.

A chave do Radar só é aceite pelo plugin para a lista de ameaças — nunca para
atualizações do plugin. Vem do segredo POTAMUS_DEFINITIONS_KEY (base64, PKCS#8),
criado no Potamus Assinador.

Proteções antes de publicar:
  * a lista nova não pode ter menos de metade das vulnerabilidades da publicada
    (sinal de erro na recolha) — nesse caso nada é publicado;
  * as expressões dos padrões são copiadas da lista publicada, não da recolha;
  * a versão é sempre mais recente do que a publicada.

Uso: POTAMUS_DEFINITIONS_KEY=... python3 tools/sign-definitions.py radar/state.json definitions.json
"""
import base64
import datetime as dt
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key

KEEP_FIELDS = ("type", "slug", "min_version", "max_version", "fixed_in", "severity", "title", "cve", "url", "exploited")
MIN_RATIO = 0.5


def fail(msg):
    print("ERRO: " + msg, file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 3:
        fail("uso: sign-definitions.py <state.json> <definitions.json>")
    state_path, out_path = sys.argv[1], sys.argv[2]

    raw = os.environ.get("POTAMUS_DEFINITIONS_KEY", "").strip()
    if not raw:
        fail("falta o segredo POTAMUS_DEFINITIONS_KEY (Settings → Secrets and variables → Actions).")
    try:
        key = load_der_private_key(base64.b64decode(raw), password=None)
    except Exception:
        fail("o segredo POTAMUS_DEFINITIONS_KEY não é uma chave válida do Potamus Assinador.")
    if not isinstance(key, Ed25519PrivateKey):
        fail("o segredo POTAMUS_DEFINITIONS_KEY não é uma chave Ed25519.")

    state = json.load(open(state_path, encoding="utf-8"))

    current = {}
    if os.path.exists(out_path):
        try:
            current = json.loads(json.load(open(out_path, encoding="utf-8"))["payload"])
        except Exception:
            current = {}

    vulns = []
    for e in state.get("vulnerabilities", []):
        item = {k: e[k] for k in KEEP_FIELDS if k in e and e[k] not in ("", None, False)}
        if item.get("slug") and (item.get("max_version") or item.get("fixed_in")):
            vulns.append(item)

    before = len(current.get("vulnerabilities", []))
    if before and len(vulns) < before * MIN_RATIO:
        fail(f"a lista nova tem {len(vulns)} vulnerabilidades, menos de metade das {before} publicadas. Publicação cancelada.")

    version = dt.datetime.now(dt.timezone.utc).strftime("%Y.%m.%d.%H%M")
    if current.get("version") and version <= current["version"]:
        fail(f"a versão {version} não é mais recente do que a publicada ({current['version']}).")

    payload = {
        "type": "potamus-definitions",
        "version": version,
        "created": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signed_by": "radar",
        "sources": state.get("sources", []),
        # Os padrões de código malicioso são mantidos à mão em radar/state.json (nomes em inglês,
        # traduzidos pelo plugin); se não existirem, copiam-se da lista publicada.
        "patterns": state.get("patterns") or current.get("patterns", []),
        "vulnerabilities": vulns,
    }
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    signature = key.sign(("potamus-security|definitions|" + text).encode("utf-8"))

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"payload": text, "signature": base64.b64encode(signature).decode()}, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"Radar de Ameaças {version}: {len(vulns)} vulnerabilidades ({before} antes), {len(payload['patterns'])} padrões.")


if __name__ == "__main__":
    main()
