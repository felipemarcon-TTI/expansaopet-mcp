import base64
import contextvars
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse as _urlparse
from datetime import date
from pathlib import Path

import anyio
import requests
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

_token_refresh_lock = threading.Lock()

# ── Config ────────────────────────────────────────────────────────────────────

BLING_CLIENT_ID     = os.environ.get("BLING_CLIENT_ID", "")
BLING_CLIENT_SECRET = os.environ.get("BLING_CLIENT_SECRET", "")
BLING_BASE_URL      = "https://www.bling.com.br/Api/v3"
BLING_TOKEN_FILE    = Path(os.environ.get("BLING_TOKEN_FILE", str(Path.home() / ".expansaopet-bling" / "tokens.json")))

_PORT          = int(os.environ.get("PORT", 8000))
_PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
_BASE_URL      = f"https://{_PUBLIC_DOMAIN}" if _PUBLIC_DOMAIN else f"http://localhost:{_PORT}"
BLING_REDIRECT_URI = os.environ.get("BLING_REDIRECT_URI", f"{_BASE_URL}/bling/callback")
MCP_AUTH_TOKEN     = "".join(os.environ.get("MCP_AUTH_TOKEN", "").split())

# ── Multi-user auth ───────────────────────────────────────────────────────────

_current_user: contextvars.ContextVar[dict | None] = contextvars.ContextVar("current_user", default=None)


def _load_users() -> tuple[dict, dict]:
    by_token: dict[str, dict] = {}
    by_id:    dict[str, dict] = {}
    if MCP_AUTH_TOKEN:
        admin = {"id": "admin", "role": "write", "token": MCP_AUTH_TOKEN}
        by_token[MCP_AUTH_TOKEN] = admin
        by_id["admin"] = admin
    raw = os.environ.get("MCP_USERS", "[]")
    try:
        for u in json.loads(raw):
            token = "".join(u.get("token", "").split())
            uid   = u.get("id", "")
            role  = u.get("role", "read")
            if token and uid:
                user = {"id": uid, "role": role, "token": token}
                by_token[token] = user
                by_id[uid]      = user
    except Exception:
        pass
    return by_token, by_id


_users_by_token, _users_by_id = _load_users()

# ── Auth middleware ───────────────────────────────────────────────────────────

_OPEN_PATHS = frozenset({
    "/", "/version", "/bling/callback",
    "/.well-known/oauth-authorization-server", "/oauth/authorize", "/oauth/token",
})


class _AuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path", "")
            if path not in _OPEN_PATHS:
                headers = dict(scope.get("headers", []))
                auth = headers.get(b"authorization", b"").decode("latin-1")
                bearer = auth[7:] if auth.startswith("Bearer ") else ""

                if not bearer and path == "/bling/auth":
                    qs = scope.get("query_string", b"").decode()
                    bearer = dict(_urlparse.parse_qsl(qs)).get("token", "")

                user = _users_by_token.get(bearer) if bearer else None
                if not user:
                    body = b'{"error":"Unauthorized"}'
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", b'Bearer realm="ExpansaoPet MCP"'),
                        ],
                    })
                    await send({"type": "http.response.body", "body": body, "more_body": False})
                    return
                scope["_user"] = user
                _current_user.set(user)
        await self.app(scope, receive, send)


mcp = FastMCP("ExpansaoPet Bling", host="0.0.0.0", port=_PORT)

_bling_pending_state: dict[str, str] = {}


def _require_write() -> None:
    user = _current_user.get()
    if not user or user.get("role") != "write":
        uid = user.get("id", "?") if user else "anon"
        raise PermissionError(f"Usuário '{uid}' tem acesso somente leitura.")


# ── Bling helpers ─────────────────────────────────────────────────────────────

def _bling_credentials_header() -> str:
    raw = f"{BLING_CLIENT_ID}:{BLING_CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()

def _persist_refresh_token_to_railway(refresh_token: str) -> bool:
    api_token      = os.environ.get("RAILWAY_API_TOKEN", "")
    project_id     = os.environ.get("RAILWAY_PROJECT_ID", "")
    environment_id = os.environ.get("RAILWAY_ENVIRONMENT_ID", "")
    service_id     = os.environ.get("RAILWAY_SERVICE_ID", "")
    missing = [k for k, v in {"RAILWAY_API_TOKEN": api_token, "RAILWAY_PROJECT_ID": project_id, "RAILWAY_ENVIRONMENT_ID": environment_id, "RAILWAY_SERVICE_ID": service_id}.items() if not v]
    if missing or not refresh_token:
        print(f"[railway] persist skipped - missing vars: {missing}")
        return False
    query = """
    mutation variableUpsert($input: VariableUpsertInput!) {
        variableUpsert(input: $input)
    }
    """
    variables = {
        "input": {
            "projectId": project_id,
            "environmentId": environment_id,
            "serviceId": service_id,
            "name": "BLING_REFRESH_TOKEN",
            "value": refresh_token,
        }
    }
    try:
        resp = requests.post(
            "https://backboard.railway.app/graphql/v2",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            json={"query": query, "variables": variables},
            timeout=10,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            print(f"[railway] variableUpsert errors: {body['errors']}")
            return False
        print("[railway] variableUpsert OK - BLING_REFRESH_TOKEN atualizado")
        return True
    except Exception as e:
        print(f"[railway] variableUpsert exception: {e}")
        return False

def _bling_save_tokens(data: dict) -> bool:
    BLING_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLING_TOKEN_FILE.write_text(json.dumps(data))
    return _persist_refresh_token_to_railway(data.get("refresh_token", ""))

def _bling_load_tokens() -> dict | None:
    if BLING_TOKEN_FILE.exists():
        return json.loads(BLING_TOKEN_FILE.read_text())
    access  = os.environ.get("BLING_ACCESS_TOKEN", "")
    refresh = os.environ.get("BLING_REFRESH_TOKEN", "")
    if refresh:
        return {"access_token": access, "refresh_token": refresh}
    return None

def _bling_refresh_token(old_access_token: str = "") -> str:
    """Renova o access token de forma thread-safe. Se outro thread ja renovou, retorna o token atual."""
    with _token_refresh_lock:
        tokens = _bling_load_tokens()
        if not tokens:
            raise RuntimeError("Nao autenticado. Use a ferramenta `autenticar_bling` primeiro.")
        # Se o token ja foi renovado por outro thread, retorna o novo sem chamar a API
        if old_access_token and tokens.get("access_token") != old_access_token:
            return tokens["access_token"]
        resp = requests.post(
            f"{BLING_BASE_URL}/oauth/token",
            headers={"Authorization": _bling_credentials_header(), "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        )
        resp.raise_for_status()
        new_tokens = resp.json()
        _bling_save_tokens(new_tokens)
        return new_tokens["access_token"]

def _bling_get_token() -> str:
    tokens = _bling_load_tokens()
    if not tokens:
        raise RuntimeError("Nao autenticado. Use a ferramenta `autenticar_bling` primeiro.")
    return tokens["access_token"]

def _bling_get(path: str, params: dict | None = None) -> dict:
    token = _bling_get_token()
    resp = requests.get(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
    if resp.status_code == 401:
        token = _bling_refresh_token(old_access_token=token)
        resp = requests.get(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
    resp.raise_for_status()
    return resp.json()

def _bling_put(path: str, body: dict) -> dict:
    token = _bling_get_token()
    resp = requests.put(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if resp.status_code == 401:
        token = _bling_refresh_token()
        resp = requests.put(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}

def _bling_post(path: str, body: dict) -> dict:
    token = _bling_get_token()
    resp = requests.post(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if resp.status_code == 401:
        token = _bling_refresh_token()
        resp = requests.post(f"{BLING_BASE_URL}{path}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
    if not resp.ok:
        raise RuntimeError(f"Bling API {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


# ── Health check ─────────────────────────────────────────────────────────────

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> HTMLResponse:
    return HTMLResponse("ExpansaoPet MCP OK", status_code=200)


@mcp.custom_route("/version", methods=["GET"])
async def version(request: Request) -> HTMLResponse:
    return HTMLResponse("v4 - 23 tools (+ relatorio_diario; fix fluxo_de_caixa, rate limit)", status_code=200)


# ── MCP OAuth2 (para claude.ai browser connector) ────────────────────────────

_auth_codes: dict[str, dict] = {}


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": _BASE_URL,
        "authorization_endpoint": f"{_BASE_URL}/oauth/authorize",
        "token_endpoint": f"{_BASE_URL}/oauth/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "response_types_supported": ["code"],
    })


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request: Request) -> RedirectResponse:
    client_id             = request.query_params.get("client_id", "")
    redirect_uri          = request.query_params.get("redirect_uri", "")
    code_challenge        = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "plain")
    state                 = request.query_params.get("state", "")

    if not redirect_uri:
        return HTMLResponse("redirect_uri obrigatorio", status_code=400)

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id":    client_id,
        "challenge":    code_challenge,
        "method":       code_challenge_method,
        "redirect_uri": redirect_uri,
    }
    params = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{_urlparse.urlencode(params)}")


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    if not MCP_AUTH_TOKEN:
        return JSONResponse({"error": "server_error"}, status_code=500)
    try:
        form       = await request.form()
        grant_type = form.get("grant_type", "")
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    if grant_type == "authorization_code":
        code          = form.get("code", "")
        code_verifier = form.get("code_verifier", "")
        if code not in _auth_codes:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        stored = _auth_codes.pop(code)
        method = stored.get("method", "plain")
        if method == "S256":
            digest    = hashlib.sha256(code_verifier.encode()).digest()
            challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        else:
            challenge = code_verifier
        if stored["challenge"] and challenge != stored["challenge"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        user = _users_by_id.get(stored.get("client_id", ""))
        access_token = user["token"] if user else MCP_AUTH_TOKEN
        return JSONResponse({
            "access_token": access_token,
            "token_type":   "Bearer",
            "expires_in":   86400,
        })

    elif grant_type == "client_credentials":
        client_id     = form.get("client_id", "")
        client_secret = "".join(form.get("client_secret", "").split())
        user = _users_by_id.get(client_id)
        if not user or not secrets.compare_digest(client_secret.encode(), user["token"].encode()):
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        return JSONResponse({
            "access_token": user["token"],
            "token_type":   "Bearer",
            "expires_in":   86400,
        })

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


# ── Bling OAuth Routes ────────────────────────────────────────────────────────

@mcp.custom_route("/bling/auth", methods=["GET"])
async def bling_auth_route(request: Request) -> RedirectResponse:
    state = secrets.token_urlsafe(16)
    _bling_pending_state[state] = "pending"
    auth_url = (
        f"https://www.bling.com.br/Api/v3/oauth/authorize"
        f"?response_type=code&client_id={BLING_CLIENT_ID}"
        f"&redirect_uri={BLING_REDIRECT_URI}&state={state}"
    )
    return RedirectResponse(auth_url)


@mcp.custom_route("/bling/callback", methods=["GET"])
async def bling_callback_route(request: Request) -> HTMLResponse:
    code  = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code:
        return HTMLResponse("<h2>Erro: código de autorização não recebido.</h2>", status_code=400)
    if state and state not in _bling_pending_state:
        return HTMLResponse("<h2>Erro: estado inválido (possível CSRF).</h2>", status_code=400)
    if state:
        del _bling_pending_state[state]

    def _exchange():
        resp = requests.post(
            f"{BLING_BASE_URL}/oauth/token",
            headers={"Authorization": _bling_credentials_header(), "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": BLING_REDIRECT_URI},
        )
        resp.raise_for_status()
        return resp.json()

    tokens = await anyio.to_thread.run_sync(_exchange)
    railway_saved = _bling_save_tokens(tokens)

    if railway_saved:
        html = """<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:500px;margin:40px auto;padding:20px;text-align:center">
<h2 style="color:green">&#10003; Bling! conectado com sucesso!</h2>
<p>A autenticação foi concluída. Pode fechar esta aba.</p>
</body></html>"""
    else:
        refresh = tokens.get("refresh_token", "")
        access  = tokens.get("access_token", "")
        html = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:40px auto;padding:20px">
<h2 style="color:green">Bling! conectado com sucesso!</h2>
<p><strong>Atenção (admin):</strong> RAILWAY_API_TOKEN não configurado — salve manualmente o Refresh Token abaixo como variável <code>BLING_REFRESH_TOKEN</code> no Railway:</p>
<textarea rows="4" style="width:100%;font-family:monospace;font-size:12px" onclick="this.select()">{refresh}</textarea>
<p style="color:#888;font-size:13px">Access Token (expira em breve):<br>
<code style="font-size:11px;word-break:break-all">{access}</code></p>
<p>Pode fechar esta aba.</p>
</body></html>"""
    return HTMLResponse(html)


# ── Bling Tools ───────────────────────────────────────────────────────────────

@mcp.tool()
def autenticar_bling() -> str:
    """(ExpansaoPet) Inicia o fluxo OAuth com o Bling! e salva os tokens localmente."""
    _require_write()
    if not BLING_CLIENT_ID or not BLING_CLIENT_SECRET:
        return "Configure as variáveis BLING_CLIENT_ID e BLING_CLIENT_SECRET antes de autenticar."
    state = secrets.token_urlsafe(16)
    _bling_pending_state[state] = "pending"
    auth_url = (
        f"https://www.bling.com.br/Api/v3/oauth/authorize"
        f"?response_type=code&client_id={BLING_CLIENT_ID}"
        f"&redirect_uri={BLING_REDIRECT_URI}&state={state}"
    )
    return (
        f"Abra esta URL no browser para autenticar com o Bling!:\n\n{auth_url}\n\n"
        f"Após autorizar, você será redirecionado para {BLING_REDIRECT_URI} automaticamente."
    )


@mcp.tool()
def listar_produtos_bling(nome: str = "", pagina: int = 1, limite: int = 100) -> str:
    """(ExpansaoPet) Lista produtos do Bling!. Filtra por nome se informado."""
    params: dict = {"pagina": pagina, "limite": limite}
    if nome:
        params["nome"] = nome
    produtos = _bling_get("/produtos", params).get("data", [])
    if not produtos:
        return "Nenhum produto encontrado."
    linhas = [
        f"- [{p['id']}] {p['nome']} | Código: {p.get('codigo') or '-'} | Preço: R$ {p.get('preco', 0):.2f}"
        for p in produtos
    ]
    return f"**{len(produtos)} produto(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_contatos_bling(nome: str = "", pagina: int = 1, limite: int = 100) -> str:
    """(ExpansaoPet) Lista contatos (clientes/fornecedores) do Bling!. Filtra por nome se informado."""
    params: dict = {"pagina": pagina, "limite": limite}
    if nome:
        params["nome"] = nome
    contatos = _bling_get("/contatos", params).get("data", [])
    if not contatos:
        return "Nenhum contato encontrado."
    linhas = [
        f"- [{c['id']}] {c['nome']} | {c.get('email') or '-'} | {c.get('telefone') or '-'}"
        for c in contatos
    ]
    return f"**{len(contatos)} contato(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def listar_pedidos_venda_bling(pagina: int = 1, limite: int = 100, situacao: int = 0) -> str:
    """
    (ExpansaoPet) Lista pedidos de venda do Bling!.
    situacao: 0=todos, 6=em aberto, 9=atendido, 12=cancelado
    """
    params: dict = {"pagina": pagina, "limite": limite}
    if situacao:
        params["idSituacao"] = situacao
    pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
    if not pedidos:
        return "Nenhum pedido encontrado."
    linhas = [
        f"- [{p['id']}] {p.get('data', '-')} | {p.get('contato', {}).get('nome', '?')} | "
        f"R$ {p.get('totalProdutos', 0):.2f} | {p.get('situacao', {}).get('nome', '-')}"
        for p in pedidos
    ]
    return f"**{len(pedidos)} pedido(s) encontrado(s):**\n" + "\n".join(linhas)


@mcp.tool()
def buscar_pedido_bling(id_pedido: int) -> str:
    """(ExpansaoPet) Busca os detalhes completos de um pedido de venda pelo ID, incluindo itens."""
    pedido = _bling_get(f"/pedidos/vendas/{id_pedido}").get("data", {})
    if not pedido:
        return f"Pedido {id_pedido} nao encontrado."

    contato  = pedido.get("contato", {}).get("nome", "?")
    data     = pedido.get("data", "-")
    situacao = pedido.get("situacao", {}).get("nome", "-")
    total    = pedido.get("totalProdutos", 0)
    obs      = pedido.get("observacoes", "")

    itens = pedido.get("itens", [])
    if itens:
        linhas_itens = []
        for item in itens:
            produto   = item.get("produto", {})
            nome_prod = produto.get("nome") or item.get("descricao") or "-"
            codigo    = produto.get("codigo") or "-"
            qtd       = item.get("quantidade", 0)
            valor     = item.get("valor", 0)
            subtotal  = qtd * valor
            linhas_itens.append(
                f"  - {nome_prod} | Cod: {codigo} | {qtd}x R$ {valor:.2f} = R$ {subtotal:.2f}"
            )
        itens_str = "\n".join(linhas_itens)
    else:
        itens_str = "  (sem itens)"

    resultado = (
        f"**Pedido #{id_pedido}**\n"
        f"- Data: {data}\n"
        f"- Cliente: {contato}\n"
        f"- Situacao: {situacao}\n"
        f"- Total: R$ {total:.2f}\n"
    )
    if obs:
        resultado += f"- Observacoes: {obs}\n"
    resultado += f"\n**Itens ({len(itens)}):**\n{itens_str}"
    return resultado


@mcp.tool()
def relatorio_mais_vendidos_bling(data_inicio: str = "2026-01-01", data_fim: str = "", top_n: int = 20, situacao: int = 9) -> str:
    """(ExpansaoPet) Produtos mais vendidos no periodo. data_inicio/data_fim: YYYY-MM-DD. top_n: quantidade (pad 20). situacao: 0=todos,6=aberto,9=atendido(pad),12=cancelado."""
    from collections import defaultdict
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import date as _date

    if not data_fim:
        data_fim = str(_date.today())

    todos_ids: list[int] = []
    pagina = 1
    while True:
        params: dict = {"pagina": pagina, "limite": 100, "dataInicial": data_inicio, "dataFinal": data_fim}
        if situacao:
            params["idSituacao"] = situacao
        data = _bling_get("/pedidos/vendas", params).get("data", [])
        if not data:
            break
        todos_ids.extend([p["id"] for p in data])
        if len(data) < 100:
            break
        pagina += 1

    if not todos_ids:
        return "Nenhum pedido encontrado no periodo " + data_inicio + " a " + data_fim + "."

    def _buscar(id_pedido: int) -> dict:
        try:
            return _bling_get(f"/pedidos/vendas/{id_pedido}").get("data", {})
        except Exception:
            return {}

    produtos: dict = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_buscar, id_p): id_p for id_p in todos_ids}
        for fut in as_completed(futures):
            pedido = fut.result()
            if not pedido:
                continue
            for item in pedido.get("itens", []):
                prod = item.get("produto", {})
                nome = prod.get("nome") or item.get("descricao") or "?"
                codigo = prod.get("codigo") or ""
                chave = codigo if codigo else nome  # codigo e chave unica; fallback em nome
                qtd = float(item.get("quantidade", 0))
                valor = float(item.get("valor", 0))
                if chave not in produtos:
                    produtos[chave] = {"nome": nome, "codigo": codigo, "qtd": 0.0, "receita": 0.0, "pedidos": 0}
                produtos[chave]["qtd"] += qtd
                produtos[chave]["receita"] += qtd * valor
                produtos[chave]["pedidos"] += 1

    if not produtos:
        return "Nenhum produto encontrado nos pedidos do periodo."

    ranking = sorted(produtos.values(), key=lambda x: x["qtd"], reverse=True)[:top_n]
    header = "**Produtos Mais Vendidos (" + data_inicio + " a " + data_fim + ") - " + str(len(todos_ids)) + " pedidos**"
    linhas = [header, ""]
    linhas.append("| # | Produto | Cod | Qtd Vendida | Receita Total | Em Pedidos |")
    linhas.append("|---|---------|-----|-------------|---------------|------------|")
    for i, dados in enumerate(ranking, 1):
        nome_curto = (dados["nome"][:57] + "...") if len(dados["nome"]) > 60 else dados["nome"]
        row = "| " + str(i) + " | " + nome_curto + " | " + (dados["codigo"] or "-")
        row += " | " + str(int(dados["qtd"])) + " | R$ " + format(dados["receita"], ".2f") + " | " + str(dados["pedidos"]) + " |"
        linhas.append(row)

    return chr(10).join(linhas)

@mcp.tool()
def consultar_estoque_bling(id_produto: int) -> str:
    """(ExpansaoPet) Consulta o saldo de estoque de um produto pelo seu ID."""
    token = _bling_get_token()
    # Endpoint requer colchetes literais na query string — não usar params={}
    url = f"{BLING_BASE_URL}/estoques/saldos?idsProdutos[]={id_produto}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 401:
        token = _bling_refresh_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    items = resp.json().get("data", [])
    if not items:
        return f"Produto {id_produto} não encontrado no estoque."
    saldo_fisico  = sum(i.get("saldoFisicoTotal",  i.get("saldoFisico",  0)) for i in items)
    saldo_virtual = sum(i.get("saldoVirtualTotal", i.get("saldoVirtual", 0)) for i in items)
    depositos = [
        f"  - {i.get('deposito', {}).get('descricao', 'Geral')}: "
        f"{i.get('saldoFisicoTotal', i.get('saldoFisico', 0))} unid."
        for i in items
    ]
    return (
        f"**Estoque do produto {id_produto}:**\n"
        f"- Saldo físico total: {saldo_fisico}\n"
        f"- Saldo virtual total: {saldo_virtual}\n"
        f"- Por depósito:\n" + "\n".join(depositos)
    )


@mcp.tool()
def atualizar_produto_bling(id_produto: int, preco: float = 0.0, nome: str = "", codigo: str = "") -> str:
    """(ExpansaoPet) Atualiza preço, nome e/ou código de um produto no Bling! pelo seu ID."""
    _require_write()
    if not preco and not nome and not codigo:
        return "Nenhum campo informado para atualizar."
    produto = _bling_get(f"/produtos/{id_produto}").get("data", {})
    if not produto:
        return f"Produto {id_produto} não encontrado."
    if produto.get("formato") == "V":
        var_data = _bling_get(f"/produtos/variacoes/{id_produto}")
        produto_completo = var_data.get("data", {})
        variacoes = produto_completo.get("variacoes", [])
        if not variacoes:
            return (
                f"Produto [{id_produto}] é variável (formato=V) mas não possui variações "
                f"cadastradas inline — use o ID de uma variação específica."
            )
        produto = produto_completo
    if preco > 0:
        produto["preco"] = preco
    if nome:
        produto["nome"] = nome
    if codigo:
        produto["codigo"] = codigo
    _bling_put(f"/produtos/{id_produto}", produto)
    partes = []
    if preco > 0: partes.append(f"preço=R$ {preco:.2f}")
    if nome:      partes.append(f"nome={nome}")
    if codigo:    partes.append(f"código={codigo}")
    return f"✓ Produto [{id_produto}] atualizado | {' | '.join(partes)}"


@mcp.tool()
def criar_pedido_venda_bling(id_contato: int, itens: list[dict], numero_pedido_externo: str = "", observacoes: str = "") -> str:
    """(ExpansaoPet) Cria pedido de venda no Bling. itens: lista de dicts {id_produto_bling, descricao, quantidade, valor}."""
    _require_write()
    bling_itens = []
    for item in itens:
        i: dict = {
            "quantidade": item.get("quantidade", 1),
            "valor":      item.get("valor", 0),
            "tipo":       item.get("tipo", "P"),
            "unidade":    item.get("unidade", "UN"),
        }
        if item.get("id_produto_bling"):
            i["produto"] = {"id": item["id_produto_bling"]}
        else:
            i["descricao"] = item.get("descricao", "")
        bling_itens.append(i)
    body: dict = {
        "contato": {"id": id_contato},
        "data":    date.today().isoformat(),
        "itens":   bling_itens,
    }
    if numero_pedido_externo:
        body["numeroPedidoCompra"] = numero_pedido_externo
    if observacoes:
        body["observacoes"] = observacoes
    pedido = _bling_post("/pedidos/vendas", body).get("data", {})
    return f"✓ Pedido de venda #{pedido.get('id', '?')} criado no Bling!"



# ── Financeiro ────────────────────────────────────────────────────────────────

@mcp.tool()
def resumo_financeiro(periodo: str = "mes") -> str:
    """(ExpansaoPet) Faturamento do dia, semana ou mes com comparativo do periodo anterior. periodo: dia, semana ou mes."""
    from datetime import timedelta
    hoje = date.today()
    if periodo == "dia":
        inicio = hoje
        inicio_ant, fim_ant = hoje - timedelta(days=1), hoje - timedelta(days=1)
        label, label_ant = "hoje", "ontem"
    elif periodo == "semana":
        inicio = hoje - timedelta(days=hoje.weekday())
        inicio_ant = inicio - timedelta(weeks=1)
        fim_ant = inicio - timedelta(days=1)
        label, label_ant = "esta semana", "semana passada"
    else:
        inicio = hoje.replace(day=1)
        inicio_ant = hoje.replace(year=hoje.year - 1, month=12, day=1) if hoje.month == 1 else hoje.replace(month=hoje.month - 1, day=1)
        fim_ant = inicio - timedelta(days=1)
        label, label_ant = "este mes", "mes passado"
    def _fat(d1, d2):
        params = {"dataInicial": str(d1), "dataFinal": str(d2), "idSituacao": 9, "pagina": 1, "limite": 100}
        total, count, pag = 0.0, 0, 1
        while True:
            params["pagina"] = pag
            pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
            if not pedidos:
                break
            for p in pedidos:
                total += float(p.get("totalProdutos", 0) or 0)
                count += 1
            if len(pedidos) < 100:
                break
            pag += 1
        return total, count
    ta, ca = _fat(inicio, hoje)
    tp, cp = _fat(inicio_ant, fim_ant)
    variacao = ((ta - tp) / tp * 100) if tp > 0 else 0
    sinal = "+" if variacao >= 0 else "-"
    tm = ta / ca if ca > 0 else 0
    return (
        f"**Resumo Financeiro - {label.capitalize()}**\n\n"
        f"- Faturamento: R$ {ta:,.2f}\n- Pedidos atendidos: {ca}\n- Ticket medio: R$ {tm:,.2f}\n\n"
        f"**Comparativo ({label_ant}):** R$ {tp:,.2f} ({cp} pedidos)\nVariacao: {sinal} {abs(variacao):.1f}%"
    )


@mcp.tool()
def contas_a_receber(dias_proximos: int = 30, incluir_vencidas: bool = True) -> str:
    """(ExpansaoPet) Contas a receber em aberto - vencendo nos proximos N dias e vencidas."""
    from datetime import timedelta
    hoje = date.today()
    data_ini = str(hoje - timedelta(days=365)) if incluir_vencidas else str(hoje)
    contas = _bling_get("/contas/receber", {
        "dataVencimentoInicial": data_ini,
        "dataVencimentoFinal": str(hoje + timedelta(days=dias_proximos)),
        "situacao": 1, "pagina": 1, "limite": 100,
    }).get("data", [])
    if not contas:
        return "Nenhuma conta a receber encontrada no periodo."
    hs = str(hoje)
    venc = [c for c in contas if c.get("dataVencimento", "") < hs]
    aven = [c for c in contas if c.get("dataVencimento", "") >= hs]
    tv = sum(float(c.get("valor", 0)) for c in venc)
    ta = sum(float(c.get("valor", 0)) for c in aven)
    L = [f"**Contas a Receber - Total: R$ {tv+ta:,.2f}**\n"]
    if venc:
        L.append(f"VENCIDAS ({len(venc)}) - R$ {tv:,.2f}:")
        for c in sorted(venc, key=lambda x: x.get("dataVencimento", "")):
            nome = c.get("contato", {}).get("nome", "?")
            L.append(f"  - {c.get('dataVencimento')} | {nome} | R$ {float(c.get('valor', 0)):,.2f}")
    if aven:
        L.append(f"\nA VENCER ({len(aven)}) - R$ {ta:,.2f}:")
        for c in sorted(aven, key=lambda x: x.get("dataVencimento", "")):
            nome = c.get("contato", {}).get("nome", "?")
            L.append(f"  - {c.get('dataVencimento')} | {nome} | R$ {float(c.get('valor', 0)):,.2f}")
    return "\n".join(L)


@mcp.tool()
def contas_a_pagar(dias_proximos: int = 30, incluir_vencidas: bool = True) -> str:
    """(ExpansaoPet) Contas a pagar em aberto - vencendo nos proximos N dias e vencidas."""
    from datetime import timedelta
    hoje = date.today()
    data_ini = str(hoje - timedelta(days=365)) if incluir_vencidas else str(hoje)
    contas = _bling_get("/contas/pagar", {
        "dataVencimentoInicial": data_ini,
        "dataVencimentoFinal": str(hoje + timedelta(days=dias_proximos)),
        "situacao": 1, "pagina": 1, "limite": 100,
    }).get("data", [])
    if not contas:
        return "Nenhuma conta a pagar encontrada no periodo."
    hs = str(hoje)
    venc = [c for c in contas if c.get("dataVencimento", "") < hs]
    aven = [c for c in contas if c.get("dataVencimento", "") >= hs]
    tv = sum(float(c.get("valor", 0)) for c in venc)
    ta = sum(float(c.get("valor", 0)) for c in aven)
    L = [f"**Contas a Pagar - Total: R$ {tv+ta:,.2f}**\n"]
    if venc:
        L.append(f"VENCIDAS ({len(venc)}) - R$ {tv:,.2f}:")
        for c in sorted(venc, key=lambda x: x.get("dataVencimento", "")):
            nome = c.get("contato", {}).get("nome", "?")
            L.append(f"  - {c.get('dataVencimento')} | {nome} | R$ {float(c.get('valor', 0)):,.2f}")
    if aven:
        L.append(f"\nA VENCER ({len(aven)}) - R$ {ta:,.2f}:")
        for c in sorted(aven, key=lambda x: x.get("dataVencimento", "")):
            nome = c.get("contato", {}).get("nome", "?")
            L.append(f"  - {c.get('dataVencimento')} | {nome} | R$ {float(c.get('valor', 0)):,.2f}")
    return "\n".join(L)


@mcp.tool()
def fluxo_de_caixa(dias_proximos: int = 30) -> str:
    """(ExpansaoPet) Entradas (contas a receber) vs saidas (contas a pagar) nos proximos N dias."""
    from datetime import timedelta
    hoje = date.today()
    pb = {
        "dataVencimentoInicial": str(hoje),
        "dataVencimentoFinal": str(hoje + timedelta(days=dias_proximos)),
        "situacao": 1, "pagina": 1, "limite": 100,
    }
    entradas = _bling_get("/contas/receber", pb).get("data", [])
    saidas   = _bling_get("/contas/pagar",   pb).get("data", [])
    te = sum(float(c.get("valor", 0)) for c in entradas)
    ts = sum(float(c.get("valor", 0)) for c in saidas)
    saldo = te - ts
    status = "OK" if saldo >= 0 else "ATENCAO"
    def _dt(c):
        v = c.get("dataVencimento")
        try:
            return date.fromisoformat(v) if v else date(9999, 1, 1)
        except (ValueError, TypeError):
            return date(9999, 1, 1)

    L = [
        f"**Fluxo de Caixa - Proximos {dias_proximos} dias**\n",
        f"- Entradas previstas: R$ {te:,.2f} ({len(entradas)} contas)",
        f"- Saidas previstas:   R$ {ts:,.2f} ({len(saidas)} contas)",
        f"- Saldo projetado [{status}]: R$ {saldo:,.2f}",
        "\n**Por semana:**",
    ]
    for s in range(0, dias_proximos, 7):
        ini = hoje + timedelta(days=s)
        fim = hoje + timedelta(days=min(s + 6, dias_proximos))
        e  = sum(float(c.get("valor", 0)) for c in entradas if ini <= _dt(c) <= fim)
        sg = sum(float(c.get("valor", 0)) for c in saidas   if ini <= _dt(c) <= fim)
        L.append(f"  {ini.strftime('%d/%m')}-{fim.strftime('%d/%m')}: +R$ {e:,.2f} / -R$ {sg:,.2f} = R$ {e-sg:,.2f}")
    return "\n".join(L)


# ── Estoque ───────────────────────────────────────────────────────────────────

@mcp.tool()
def alertas_estoque_baixo(limite: int = 100) -> str:
    """(ExpansaoPet) Lista produtos com estoque fisico abaixo do minimo cadastrado ou zerado."""
    from concurrent.futures import ThreadPoolExecutor
    produtos = _bling_get("/produtos", {"pagina": 1, "limite": limite}).get("data", [])
    if not produtos:
        return "Nenhum produto encontrado."
    def _saldo(prod: dict) -> dict:
        try:
            url = f"{BLING_BASE_URL}/estoques/saldos?idsProdutos[]={prod['id']}"
            token = _bling_get_token()
            resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 401:
                token = _bling_refresh_token()
                resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
            saldo = sum(i.get("saldoFisicoTotal", i.get("saldoFisico", 0)) for i in resp.json().get("data", []))
        except Exception:
            saldo = None
        return {"prod": prod, "saldo": saldo}
    alertas = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_saldo, produtos):
            if r["saldo"] is None:
                continue
            prod = r["prod"]
            minimo = float(prod.get("estoqueMinimo", 0) or 0)
            if r["saldo"] <= minimo:
                alertas.append({
                    "id": prod["id"], "nome": prod.get("nome", "?"),
                    "codigo": prod.get("codigo", "-"), "saldo": r["saldo"], "minimo": minimo,
                })
    if not alertas:
        return "Nenhum produto com estoque abaixo do minimo."
    alertas.sort(key=lambda x: x["saldo"])
    L = [f"ALERTA: {len(alertas)} produto(s) com estoque critico:\n"]
    for a in alertas:
        status = "ZERADO" if a["saldo"] == 0 else "BAIXO"
        L.append(f"- [{status}] [{a['id']}] {a['nome']} | Cod: {a['codigo']} | Estoque: {a['saldo']} | Minimo: {a['minimo']}")
    return "\n".join(L)


@mcp.tool()
def produtos_sem_movimento(dias: int = 30, limite_produtos: int = 100) -> str:
    """(ExpansaoPet) Produtos cadastrados que nao aparecem em nenhum pedido nos ultimos N dias."""
    from datetime import timedelta
    hoje = date.today()
    produtos = _bling_get("/produtos", {"pagina": 1, "limite": limite_produtos}).get("data", [])
    if not produtos:
        return "Nenhum produto encontrado."
    params = {"dataInicial": str(hoje - timedelta(days=dias)), "dataFinal": str(hoje), "pagina": 1, "limite": 100}
    ids_vendidos: set = set()
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        for p in pedidos:
            for item in p.get("itens", []):
                id_prod = item.get("produto", {}).get("id")
                if id_prod:
                    ids_vendidos.add(id_prod)
        if len(pedidos) < 100:
            break
        pagina += 1
    parados = [p for p in produtos if p["id"] not in ids_vendidos]
    if not parados:
        return f"Todos os produtos tiveram movimento nos ultimos {dias} dias."
    L = [f"**{len(parados)} produto(s) sem movimento nos ultimos {dias} dias:**\n"]
    for p in parados:
        L.append(f"- [{p['id']}] {p['nome']} | Cod: {p.get('codigo') or '-'} | Preco: R$ {p.get('preco', 0):.2f}")
    return "\n".join(L)


@mcp.tool()
def sugestao_reposicao(dias_analise: int = 30, dias_cobertura: int = 30, limite: int = 100) -> str:
    """(ExpansaoPet) Sugere reposicao de estoque com base na velocidade de venda dos ultimos N dias."""
    from datetime import timedelta
    from concurrent.futures import ThreadPoolExecutor
    hoje = date.today()
    params = {"dataInicial": str(hoje - timedelta(days=dias_analise)), "dataFinal": str(hoje), "idSituacao": 9, "pagina": 1, "limite": 100}
    vendas: dict = {}
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        for p in pedidos:
            for item in p.get("itens", []):
                id_prod = item.get("produto", {}).get("id")
                if not id_prod:
                    continue
                qtd = float(item.get("quantidade", 0))
                if id_prod not in vendas:
                    vendas[id_prod] = {"nome": item.get("produto", {}).get("nome") or item.get("descricao", "?"), "qtd": 0.0}
                vendas[id_prod]["qtd"] += qtd
        if len(pedidos) < 100:
            break
        pagina += 1
    if not vendas:
        return "Nenhuma venda encontrada no periodo para calcular reposicao."
    def _saldo(id_prod: int) -> tuple:
        try:
            url = f"{BLING_BASE_URL}/estoques/saldos?idsProdutos[]={id_prod}"
            resp = requests.get(url, headers={"Authorization": f"Bearer {_bling_get_token()}"})
            time.sleep(0.35)
            return id_prod, float(sum(i.get("saldoFisicoTotal", i.get("saldoFisico", 0)) for i in resp.json().get("data", [])))
        except Exception:
            return id_prod, 0.0
    with ThreadPoolExecutor(max_workers=2) as ex:
        for id_p, saldo in ex.map(_saldo, list(vendas.keys())[:limite]):
            vendas[id_p]["estoque"] = saldo
    sugestoes = []
    for d in vendas.values():
        qtd_dia = d["qtd"] / dias_analise
        repor = max(0.0, qtd_dia * dias_cobertura - d.get("estoque", 0))
        if repor > 0:
            sugestoes.append({"nome": d["nome"], "estoque": d.get("estoque", 0), "media_dia": round(qtd_dia, 2), "repor": round(repor, 1)})
    if not sugestoes:
        return f"Estoque suficiente para todos os produtos por {dias_cobertura} dias."
    sugestoes.sort(key=lambda x: x["repor"], reverse=True)
    L = [f"**Sugestao de Reposicao - Cobertura de {dias_cobertura} dias**\n",
         "| Produto | Estoque | Vend/dia | Repor |",
         "|---------|---------|----------|-------|"]
    for s in sugestoes:
        nome_curto = (s["nome"][:40] + "...") if len(s["nome"]) > 43 else s["nome"]
        L.append(f"| {nome_curto} | {s['estoque']} | {s['media_dia']} | **{s['repor']}** |")
    return "\n".join(L)


# ── Clientes ──────────────────────────────────────────────────────────────────

@mcp.tool()
def clientes_inativos(dias: int = 60) -> str:
    """(ExpansaoPet) Clientes que nao realizaram pedidos nos ultimos N dias."""
    from datetime import timedelta
    hoje = date.today()
    data_corte = str(hoje - timedelta(days=dias))
    ativos: set = set()
    params = {"dataInicial": data_corte, "dataFinal": str(hoje), "pagina": 1, "limite": 100}
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        for p in pedidos:
            id_c = p.get("contato", {}).get("id")
            if id_c:
                ativos.add(id_c)
        if len(pedidos) < 100:
            break
        pagina += 1
        time.sleep(0.35)
    params2 = {"dataInicial": str(hoje - timedelta(days=365)), "dataFinal": data_corte, "pagina": 1, "limite": 100}
    ultimo_pedido: dict = {}
    pagina = 1
    while True:
        params2["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params2).get("data", [])
        if not pedidos:
            break
        for p in pedidos:
            contato = p.get("contato", {})
            id_c = contato.get("id")
            if not id_c or id_c in ativos:
                continue
            data_p = p.get("data", "")
            if id_c not in ultimo_pedido or data_p > ultimo_pedido[id_c]["data"]:
                ultimo_pedido[id_c] = {"nome": contato.get("nome", "?"), "data": data_p, "total": float(p.get("totalProdutos", 0))}
        if len(pedidos) < 100:
            break
        pagina += 1
        time.sleep(0.35)
    if not ultimo_pedido:
        return f"Todos os clientes compraram nos ultimos {dias} dias."
    inativos = sorted(ultimo_pedido.values(), key=lambda x: x["data"])
    L = [f"**{len(inativos)} cliente(s) inativos ha mais de {dias} dias:**\n"]
    for c in inativos:
        dias_sem = (hoje - date.fromisoformat(c["data"])).days if c["data"] else "?"
        L.append(f"- {c['nome']} | Ultimo pedido: {c['data']} ({dias_sem} dias) | R$ {c['total']:.2f}")
    return "\n".join(L)


@mcp.tool()
def top_clientes(data_inicio: str = "", data_fim: str = "", top_n: int = 10) -> str:
    """(ExpansaoPet) Ranking dos melhores clientes por valor total comprado no periodo."""
    hoje = date.today()
    if not data_inicio:
        data_inicio = str(hoje.replace(day=1))
    if not data_fim:
        data_fim = str(hoje)
    params = {"dataInicial": data_inicio, "dataFinal": data_fim, "idSituacao": 9, "pagina": 1, "limite": 100}
    clientes: dict = {}
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        for p in pedidos:
            contato = p.get("contato", {})
            id_c = contato.get("id", "sem_id")
            total = float(p.get("totalProdutos", 0) or 0)
            if id_c not in clientes:
                clientes[id_c] = {"nome": contato.get("nome", "?"), "total": 0.0, "pedidos": 0}
            clientes[id_c]["total"] += total
            clientes[id_c]["pedidos"] += 1
        if len(pedidos) < 100:
            break
        pagina += 1
    if not clientes:
        return f"Nenhum pedido atendido no periodo {data_inicio} a {data_fim}."
    ranking = sorted(clientes.values(), key=lambda x: x["total"], reverse=True)[:top_n]
    total_geral = sum(c["total"] for c in clientes.values())
    L = [f"**Top {top_n} Clientes - {data_inicio} a {data_fim}**\n",
         "| # | Cliente | Total | Pedidos | % do total |",
         "|---|---------|-------|---------|-----------|"]
    for i, c in enumerate(ranking, 1):
        pct = c["total"] / total_geral * 100 if total_geral > 0 else 0
        nome_curto = (c["nome"][:35] + "...") if len(c["nome"]) > 38 else c["nome"]
        L.append(f"| {i} | {nome_curto} | R$ {c['total']:,.2f} | {c['pedidos']} | {pct:.1f}% |")
    return "\n".join(L)


@mcp.tool()
def historico_cliente(id_contato: int, limite: int = 20) -> str:
    """(ExpansaoPet) Historico completo de pedidos e total gasto por um cliente no ultimo ano."""
    from datetime import timedelta
    hoje = date.today()
    try:
        nome = _bling_get(f"/contatos/{id_contato}").get("data", {}).get("nome", f"Contato {id_contato}")
    except Exception:
        nome = f"Contato {id_contato}"
    params = {"dataInicial": str(hoje - timedelta(days=365)), "dataFinal": str(hoje), "pagina": 1, "limite": 100}
    todos = []
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        todos.extend(p for p in pedidos if p.get("contato", {}).get("id") == id_contato)
        if len(pedidos) < 100:
            break
        pagina += 1
    if not todos:
        return f"Nenhum pedido para o cliente {id_contato} no ultimo ano."
    todos.sort(key=lambda x: x.get("data", ""), reverse=True)
    total_gasto = sum(float(p.get("totalProdutos", 0)) for p in todos)
    tm = total_gasto / len(todos)
    L = [f"**Historico de {nome}**\n",
         f"- Total de pedidos: {len(todos)}",
         f"- Total gasto (ultimo ano): R$ {total_gasto:,.2f}",
         f"- Ticket medio: R$ {tm:,.2f}\n",
         "**Ultimos pedidos:**"]
    for p in todos[:limite]:
        situacao = p.get("situacao", {}).get("nome", "-")
        L.append(f"- [{p['id']}] {p.get('data', '-')} | R$ {float(p.get('totalProdutos', 0)):,.2f} | {situacao}")
    return "\n".join(L)


# ── Operacional ───────────────────────────────────────────────────────────────

@mcp.tool()
def pedidos_pendentes(dias_atraso: int = 0) -> str:
    """(ExpansaoPet) Lista pedidos em aberto. dias_atraso > 0 mostra apenas os abertos ha N+ dias."""
    from datetime import timedelta
    params = {"idSituacao": 6, "pagina": 1, "limite": 100}
    todos = []
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        todos.extend(pedidos)
        if len(pedidos) < 100:
            break
        pagina += 1
    if not todos:
        return "Nenhum pedido em aberto no momento."
    if dias_atraso > 0:
        corte = str(date.today() - timedelta(days=dias_atraso))
        todos = [p for p in todos if p.get("data", "9999-99-99") <= corte]
    if not todos:
        return f"Nenhum pedido em aberto com mais de {dias_atraso} dias."
    hoje = date.today()
    todos.sort(key=lambda x: x.get("data", ""))
    total = sum(float(p.get("totalProdutos", 0)) for p in todos)
    L = [f"**{len(todos)} pedido(s) em aberto - R$ {total:,.2f} total**\n"]
    for p in todos:
        data_p = p.get("data", "-")
        diasd = (hoje - date.fromisoformat(data_p)).days if data_p != "-" else "?"
        cliente = p.get("contato", {}).get("nome", "?")
        L.append(f"- [{p['id']}] {data_p} ({diasd}d) | {cliente} | R$ {float(p.get('totalProdutos', 0)):,.2f}")
    return "\n".join(L)


@mcp.tool()
def resumo_do_dia() -> str:
    """(ExpansaoPet) Dashboard do dia: vendas de hoje, pedidos em aberto, contas vencidas e estoque critico."""
    from datetime import timedelta
    from concurrent.futures import ThreadPoolExecutor
    hoje = date.today()
    hs = str(hoje)
    def _vendas():
        p = _bling_get("/pedidos/vendas", {"dataInicial": hs, "dataFinal": hs, "pagina": 1, "limite": 100}).get("data", [])
        return len(p), sum(float(x.get("totalProdutos", 0)) for x in p)
    def _abertos():
        return len(_bling_get("/pedidos/vendas", {"idSituacao": 6, "pagina": 1, "limite": 100}).get("data", []))
    def _vencidas():
        pb = {"dataVencimentoInicial": str(hoje - timedelta(days=365)), "dataVencimentoFinal": str(hoje - timedelta(days=1)), "situacao": 1, "pagina": 1, "limite": 100}
        return len(_bling_get("/contas/receber", pb).get("data", [])), len(_bling_get("/contas/pagar", pb).get("data", []))
    def _criticos():
        criticos = 0
        for p in _bling_get("/produtos", {"pagina": 1, "limite": 50}).get("data", []):
            minimo = float(p.get("estoqueMinimo", 0) or 0)
            if minimo <= 0:
                continue
            try:
                url = f"{BLING_BASE_URL}/estoques/saldos?idsProdutos[]={p['id']}"
                resp = requests.get(url, headers={"Authorization": f"Bearer {_bling_get_token()}"})
                if sum(i.get("saldoFisicoTotal", i.get("saldoFisico", 0)) for i in resp.json().get("data", [])) <= minimo:
                    criticos += 1
            except Exception:
                pass
        return criticos
    with ThreadPoolExecutor(max_workers=4) as ex:
        fv = ex.submit(_vendas)
        fa = ex.submit(_abertos)
        fc = ex.submit(_vencidas)
        fe = ex.submit(_criticos)
        np, tv = fv.result()
        na = fa.result()
        rv, pv = fc.result()
        nc = fe.result()
    tm = tv / np if np > 0 else 0
    L = [f"**Dashboard - {hoje.strftime('%d/%m/%Y')}**\n",
         "**Vendas de hoje:**",
         f"- Pedidos: {np} | Faturamento: R$ {tv:,.2f} | Ticket medio: R$ {tm:,.2f}",
         "\n**Alertas:**"]
    if na: L.append(f"- {na} pedido(s) em aberto")
    if rv: L.append(f"- {rv} conta(s) a receber VENCIDA(S)")
    if pv: L.append(f"- {pv} conta(s) a pagar VENCIDA(S)")
    if nc: L.append(f"- {nc} produto(s) com estoque critico")
    if not any([na, rv, pv, nc]):
        L.append("- Nenhum alerta critico")
    return "\n".join(L)


@mcp.tool()
def ticket_medio(data_inicio: str = "", data_fim: str = "", por_cliente: bool = False) -> str:
    """(ExpansaoPet) Ticket medio do periodo. Se por_cliente=True, mostra o ticket de cada cliente."""
    hoje = date.today()
    if not data_inicio:
        data_inicio = str(hoje.replace(day=1))
    if not data_fim:
        data_fim = str(hoje)
    params = {"dataInicial": data_inicio, "dataFinal": data_fim, "idSituacao": 9, "pagina": 1, "limite": 100}
    clientes: dict = {}
    total_geral, total_pedidos = 0.0, 0
    pagina = 1
    while True:
        params["pagina"] = pagina
        pedidos = _bling_get("/pedidos/vendas", params).get("data", [])
        if not pedidos:
            break
        for p in pedidos:
            total = float(p.get("totalProdutos", 0) or 0)
            total_geral += total
            total_pedidos += 1
            if por_cliente:
                contato = p.get("contato", {})
                id_c = contato.get("id", "sem_id")
                if id_c not in clientes:
                    clientes[id_c] = {"nome": contato.get("nome", "?"), "total": 0.0, "pedidos": 0}
                clientes[id_c]["total"] += total
                clientes[id_c]["pedidos"] += 1
        if len(pedidos) < 100:
            break
        pagina += 1
    if total_pedidos == 0:
        return f"Nenhum pedido atendido no periodo {data_inicio} a {data_fim}."
    ticket = total_geral / total_pedidos
    L = [f"**Ticket Medio - {data_inicio} a {data_fim}**\n",
         f"- Total faturado: R$ {total_geral:,.2f}",
         f"- Total de pedidos: {total_pedidos}",
         f"- **Ticket medio geral: R$ {ticket:,.2f}**"]
    if por_cliente and clientes:
        L.append("\n**Por cliente:**")
        for c in sorted(clientes.values(), key=lambda x: x["total"] / x["pedidos"], reverse=True):
            tm = c["total"] / c["pedidos"]
            L.append(f"- {c['nome']}: R$ {tm:,.2f} ({c['pedidos']} pedidos, total R$ {c['total']:,.2f})")
    return "\n".join(L)


@mcp.tool()
def relatorio_diario(data: str = "") -> str:
    """(ExpansaoPet) Relatorio completo de um dia: vendas, top produtos, clientes, status dos pedidos e comparativo. data: YYYY-MM-DD (padrao: ontem)."""
    from datetime import timedelta
    from concurrent.futures import ThreadPoolExecutor, as_completed

    hoje = date.today()
    alvo = date.fromisoformat(data) if data else hoje - timedelta(days=1)
    ds = str(alvo)

    def _pag(params_base: dict) -> list:
        resultado, pag = [], 1
        p = dict(params_base)
        while True:
            p["pagina"] = pag
            itens = _bling_get("/pedidos/vendas", p).get("data", [])
            if not itens:
                break
            resultado.extend(itens)
            if len(itens) < 100:
                break
            pag += 1
            time.sleep(0.3)
        return resultado

    atendidos = _pag({"dataInicial": ds, "dataFinal": ds, "idSituacao": 9, "limite": 100})
    todos_dia  = _pag({"dataInicial": ds, "dataFinal": ds, "limite": 100})

    faturamento = sum(float(p.get("totalProdutos", 0)) for p in atendidos)
    n_pedidos   = len(atendidos)
    ticket      = faturamento / n_pedidos if n_pedidos > 0 else 0
    clientes_unicos = {p.get("contato", {}).get("nome", "?") for p in atendidos}

    # top produtos — busca detalhes apenas se volume razoavel
    produtos_dia: dict = {}
    if 0 < n_pedidos <= 30:
        def _det(pid: int) -> dict:
            try:
                return _bling_get(f"/pedidos/vendas/{pid}").get("data", {})
            except Exception:
                return {}
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = {ex.submit(_det, p["id"]): p["id"] for p in atendidos}
            for fut in as_completed(futs):
                for item in fut.result().get("itens", []):
                    prod   = item.get("produto", {})
                    nome   = prod.get("nome") or item.get("descricao") or "?"
                    codigo = prod.get("codigo") or ""
                    chave  = codigo if codigo else nome
                    qtd    = float(item.get("quantidade", 0))
                    val    = float(item.get("valor", 0))
                    if chave not in produtos_dia:
                        produtos_dia[chave] = {"nome": nome, "qtd": 0.0, "receita": 0.0}
                    produtos_dia[chave]["qtd"]     += qtd
                    produtos_dia[chave]["receita"] += qtd * val

    # comparativo: dia anterior e media dos 7 dias anteriores
    ant        = alvo - timedelta(days=1)
    atend_ant  = _pag({"dataInicial": str(ant), "dataFinal": str(ant), "idSituacao": 9, "limite": 100})
    fat_ant    = sum(float(p.get("totalProdutos", 0)) for p in atend_ant)

    semana_ini = alvo - timedelta(days=7)
    atend_7d   = _pag({"dataInicial": str(semana_ini), "dataFinal": str(ant), "idSituacao": 9, "limite": 100})
    media_7d   = sum(float(p.get("totalProdutos", 0)) for p in atend_7d) / 7 if atend_7d else 0

    def _var(atual, base):
        if base <= 0:
            return ""
        v = (atual - base) / base * 100
        return f" ({'+' if v >= 0 else ''}{v:.1f}% vs {base:,.2f})"

    L = [f"**Relatório do Dia — {alvo.strftime('%d/%m/%Y')}**\n"]

    L.append("**Vendas atendidas:**")
    L.append(f"- Pedidos: {n_pedidos}")
    L.append(f"- Faturamento: R$ {faturamento:,.2f}{_var(faturamento, fat_ant)}")
    L.append(f"- Ticket médio: R$ {ticket:,.2f}")
    L.append(f"- Clientes únicos: {len(clientes_unicos)}")
    L.append(f"- Média diária (7d anteriores): R$ {media_7d:,.2f}")

    if todos_dia:
        por_status: dict = {}
        for p in todos_dia:
            s = p.get("situacao", {}).get("nome", "?")
            por_status[s] = por_status.get(s, 0) + 1
        L.append(f"\n**Pedidos criados no dia ({len(todos_dia)} total):**")
        for s, q in sorted(por_status.items(), key=lambda x: -x[1]):
            L.append(f"  - {s}: {q}")

    if produtos_dia:
        ranking = sorted(produtos_dia.values(), key=lambda x: x["qtd"], reverse=True)[:10]
        L.append("\n**Top produtos do dia:**")
        L.append("| # | Produto | Qtd | Receita |")
        L.append("|---|---------|-----|---------|")
        for i, d in enumerate(ranking, 1):
            nome_c = (d["nome"][:40] + "...") if len(d["nome"]) > 43 else d["nome"]
            L.append(f"| {i} | {nome_c} | {int(d['qtd'])} | R$ {d['receita']:,.2f} |")
    elif n_pedidos > 30:
        L.append(f"\n_(Volume alto — {n_pedidos} pedidos. Use relatorio_mais_vendidos_bling para o ranking do período.)_")

    if clientes_unicos and n_pedidos <= 20:
        L.append("\n**Clientes que compraram:**")
        for c in sorted(clientes_unicos):
            L.append(f"  - {c}")

    if n_pedidos == 0:
        L.append("\nNenhum pedido atendido neste dia.")

    return "\n".join(L)


# ── Admin API ─────────────────────────────────────────────────────────────────

@mcp.custom_route("/admin/users", methods=["GET", "POST"])
async def admin_users(request: Request) -> JSONResponse:
    caller = request.scope.get("_user", {})
    if caller.get("role") != "write":
        return JSONResponse({"error": "Requer permissão write"}, status_code=403)

    if request.method == "GET":
        users = [{"id": u["id"], "role": u["role"]} for u in _users_by_id.values()]
        return JSONResponse(users)

    try:
        body = await request.json()
        uid  = body.get("id", "").strip()
        role = body.get("role", "read")
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if not uid:
        return JSONResponse({"error": "id é obrigatório"}, status_code=400)
    if uid in _users_by_id:
        return JSONResponse({"error": f"Usuário '{uid}' já existe"}, status_code=409)
    if role not in ("read", "write"):
        role = "read"
    token = secrets.token_urlsafe(32)
    new_user = {"id": uid, "role": role, "token": token}
    _users_by_token[token] = new_user
    _users_by_id[uid]      = new_user
    return JSONResponse({"id": uid, "token": token, "role": role}, status_code=201)


@mcp.custom_route("/admin/users/{user_id}", methods=["DELETE"])
async def admin_delete_user(request: Request) -> JSONResponse:
    caller = request.scope.get("_user", {})
    if caller.get("role") != "write":
        return JSONResponse({"error": "Requer permissão write"}, status_code=403)
    uid = request.path_params.get("user_id", "")
    if uid == "admin":
        return JSONResponse({"error": "Não é possível deletar o admin"}, status_code=400)
    target = _users_by_id.pop(uid, None)
    if not target:
        return JSONResponse({"error": f"Usuário '{uid}' não encontrado"}, status_code=404)
    _users_by_token.pop(target["token"], None)
    return JSONResponse({"deleted": uid})


@mcp.custom_route("/admin/export", methods=["GET"])
async def admin_export(request: Request) -> JSONResponse:
    caller = request.scope.get("_user", {})
    if caller.get("role") != "write":
        return JSONResponse({"error": "Requer permissão write"}, status_code=403)
    users = [
        {"id": u["id"], "token": u["token"], "role": u["role"]}
        for u in _users_by_id.values()
        if u["id"] != "admin"
    ]
    return JSONResponse(users)



# ── MCP 2024-11-05 compatibility ──────────────────────────────────────────────

def _strip_output_schema(body: bytes) -> bytes:
    if b'"outputSchema"' not in body:
        return body
    text = body.decode("utf-8", errors="replace")
    result = []
    for line in text.splitlines(keepends=True):
        if line.startswith("data: "):
            try:
                d = json.loads(line[6:])
                if isinstance(d, dict) and "tools" in d.get("result", {}):
                    for t in d["result"]["tools"]:
                        t.pop("outputSchema", None)
                        t.get("inputSchema", {}).pop("title", None)
                    line = f"data: {json.dumps(d, ensure_ascii=False)}\n"
            except Exception:
                pass
        result.append(line)
    return "".join(result).encode("utf-8")


class _McpCompatMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "") not in ("/mcp", "/messages/"):
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        start_msg: dict = {}

        async def _send(msg):
            if msg["type"] == "http.response.start":
                start_msg.update(msg)
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    full = _strip_output_schema(b"".join(chunks))
                    hdrs = [
                        (k, str(len(full)).encode() if k == b"content-length" else v)
                        for k, v in start_msg.get("headers", [])
                    ]
                    await send({**start_msg, "headers": hdrs})
                    await send({"type": "http.response.body", "body": full, "more_body": False})

        await self.app(scope, receive, _send)


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    class _CombinedApp:
        def __init__(self, http_app, sse_app):
            self.http_app = http_app
            self.sse_app = sse_app

        async def __call__(self, scope, receive, send):
            path = scope.get("path", "")
            if path == "/sse" or path.startswith("/messages"):
                await self.sse_app(scope, receive, send)
            else:
                await self.http_app(scope, receive, send)

    combined = _CombinedApp(mcp.streamable_http_app(), mcp.sse_app())
    uvicorn.run(_McpCompatMiddleware(_AuthMiddleware(combined)), host="0.0.0.0", port=_PORT)
