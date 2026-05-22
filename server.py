import base64
import contextvars
import hashlib
import json
import os
import secrets
import threading
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
BLING_TOKEN_FILE    = Path.home() / ".expansaopet-bling" / "tokens.json"

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
    if not all([api_token, project_id, environment_id, service_id, refresh_token]):
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
        requests.post(
            "https://backboard.railway.app/graphql/v2",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            json={"query": query, "variables": variables},
            timeout=10,
        )
        return True
    except Exception:
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
    return HTMLResponse("v2 - 9 tools (buscar_pedido + relatorio_mais_vendidos)", status_code=200)


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
