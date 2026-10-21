param([switch] $ProbeLlm)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker est absent du PATH. Demarre Docker Desktop avant de preparer la demonstration.'
}

Push-Location $projectRoot
try {
    $runningServices = @(& docker compose --profile assistant ps --status running --services)
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Compose ne repond pas. Verifie que Docker Desktop est demarre.'
    }
    $missing = @('assistant', 'ollama' | Where-Object { $runningServices -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw ('Services inactifs : ' + ($missing -join ', ') + '. Lance : docker compose --profile assistant up -d --build web assistant')
    }

    Write-Host 'Prechauffage du modele local avant la demonstration (jusqu a 60 secondes).'
    # The token is read only inside the assistant container. It never enters a
    # command argument, host variable, temporary file or diagnostic output.
    $pythonCode = @'
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    token = Path(os.environ['CYBERSHIELD_ASSISTANT_TOKEN_FILE']).read_text(encoding='utf-8').strip()
except (OSError, KeyError, UnicodeError):
    print('ECHEC : jeton interne assistant inaccessible.', flush=True)
    raise SystemExit(1)
if len(token) < 32:
    print('ECHEC : jeton interne assistant invalide.', flush=True)
    raise SystemExit(1)

def call(route, body=None, timeout=3):
    data = None if body is None else json.dumps(body).encode('utf-8')
    headers = {'Accept': 'application/json'}
    if body is not None:
        headers.update({'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    req = Request('http://127.0.0.1:5100' + route, data=data, headers=headers,
                  method='GET' if body is None else 'POST')
    started = time.perf_counter()
    try:
        with urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read(65537).decode('utf-8'))
            return response.status, payload if isinstance(payload, dict) else {}, (time.perf_counter() - started) * 1000
    except HTTPError as error:
        return error.code, {}, (time.perf_counter() - started) * 1000
    except (URLError, TimeoutError, OSError, ValueError):
        print('ECHEC : appel interne ' + route + ' indisponible ou delai depasse.', flush=True)
        raise SystemExit(1)

status, health, _ = call('/health')
if status != 200 or health.get('service_available') is not True:
    print('ECHEC : service assistant indisponible (HTTP ' + str(status) + ').', flush=True)
    raise SystemExit(1)
# Inventory may still be refreshing after service startup. Only a real warmup
# determines whether the configured model can be loaded; do not treat an
# unknown/cached model_installed value as evidence that the model is absent.
status, warm, elapsed = call('/warmup', {}, timeout=75)
print('Prechauffage : HTTP ' + str(status) + ', ' + str(round(elapsed)) + ' ms.', flush=True)
if status != 200 or warm.get('status') != 'ready' or warm.get('loaded') is not True:
    print('ECHEC : modele non charge. Verifie les services avant la demonstration.', flush=True)
    raise SystemExit(1)

status, health, _ = call('/health', timeout=5)
model = str(health.get('model', ''))
model = model if re.fullmatch(r'[A-Za-z0-9._:-]{1,80}', model) else 'modele configure'
loaded = health.get('model_loaded') is True
print('Modele : ' + model + ' ; charge=' + str(loaded).lower() + '.', flush=True)
if status != 200 or health.get('service_available') is not True or not loaded:
    print('ECHEC : le controle apres prechauffage ne confirme pas le modele en memoire.', flush=True)
    raise SystemExit(1)

status, greeting, elapsed = call('/chat', {'question': 'salut', 'context': {}}, timeout=3)
source = 'local' if greeting.get('source') == 'local' else 'inattendue'
print('Reponse locale : HTTP ' + str(status) + ', source=' + source + ', ' + str(round(elapsed, 1)) + ' ms.', flush=True)
if status != 200 or greeting.get('status') != 'ok' or greeting.get('source') != 'local' or not greeting.get('answer') or elapsed >= 1000:
    print('ECHEC : la reponse locale immediate doit fonctionner en moins de 1 seconde.', flush=True)
    raise SystemExit(1)

if len(sys.argv) > 1 and sys.argv[1] == '1':
    status, probe, elapsed = call('/chat', {
        'question': 'En une phrase, pourquoi une requete preparee limite-t-elle les injections SQL ?',
        'context': {},
    }, timeout=12)
    print('Test LLM : HTTP ' + str(status) + ', ' + str(round(elapsed)) + ' ms.', flush=True)
    if status != 200 or probe.get('status') != 'ok' or probe.get('source') != 'llm' or not probe.get('answer'):
        print('ECHEC : aucune reponse LLM complete valide dans le delai ; les reponses locales restent disponibles.', flush=True)
        raise SystemExit(2)

print('Preparation terminee : modele charge et reponse locale rapide verifies.', flush=True)
'@
    $probeArgument = if ($ProbeLlm) { '1' } else { '0' }
    $pythonCode | & docker compose exec -T assistant python - $probeArgument
    if ($LASTEXITCODE -ne 0) {
        throw 'La preparation de la demonstration a echoue. Aucun redemarrage ni telechargement automatique n a ete effectue.'
    }
    Write-Host 'Ouvre http://127.0.0.1:8080/security/assistant.php puis actualise avec Ctrl+F5.'
} finally {
    Pop-Location
}
