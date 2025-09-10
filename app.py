# Lista 2 — App de pré-correção (lê casos com HASH de /s no GitHub)
import streamlit as st
import io, sys, builtins, json, re, hashlib, requests
import pandas as _pd

# =========================
# Configurações
# =========================
st.set_page_config(page_title="Lista 2 — Meninas Programadoras", layout="centered")
LISTA_ID = "Lista 2"

# Secrets (defina na Cloud; localmente pode deixar os defaults)
# >>>> Para repo PRIVADO use a API contents + token <<<<
# ex.: GITHUB_RAW_BASE = "https://api.github.com/repos/mgpimentel/xyzist3st3s/contents/s"
GITHUB_RAW_BASE = st.secrets.get("GITHUB_RAW_BASE", None)
GITHUB_BRANCH   = st.secrets.get("GITHUB_BRANCH", "main")
GITHUB_TOKEN    = st.secrets.get("GITHUB_TOKEN", None)   # obrigatório se o repo for privado

TIME_LIMIT_SEC  = float(st.secrets.get("TIME_LIMIT_SEC", 4.0))
OUTPUT_LIMIT    = int(st.secrets.get("OUTPUT_LIMIT", 10000))

# multiprocessing seguro (evita travas no Windows)
try:
    import multiprocessing as _mp
    _mp.set_start_method("spawn", force=True)
except Exception:
    pass

# =========================
# Helpers
# =========================
def _sha256(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

def _normalize(s: str, mode: str = "strip") -> str:
    s = (s or "").replace("\r\n", "\n").replace("\r", "\n")
    if mode == "strip":  return s.strip()
    if mode == "rstrip": return s.rstrip()
    if mode == "lstrip": return s.lstrip()
    return s  # "none"

def _worker_exec(code: str, input_text: str, queue):
    """Executa o código do/a aluno/a em processo separado e retorna (status, saida)."""
    import io, sys, builtins
    lines = (input_text or "").splitlines(True)
    it = iter(lines)
    def fake_input(prompt=""):
        try:
            return next(it).rstrip("\n")
        except StopIteration:
            raise EOFError("faltou entrada para input()")
    old_stdin, old_stdout = sys.stdin, sys.stdout
    old_input = builtins.input
    sys.stdin = io.StringIO(input_text or "")
    sys.stdout = io.StringIO()
    builtins.input = fake_input
    try:
        exec(code or "", {})
        queue.put(("ok", sys.stdout.getvalue()))
    except Exception as e:
        queue.put(("exc", f"{type(e).__name__}: {e}"))
    finally:
        sys.stdin, sys.stdout = old_stdin, old_stdout
        builtins.input = old_input

def run_user_code(code: str, input_text: str, time_limit: float = TIME_LIMIT_SEC, output_limit: int = OUTPUT_LIMIT):
    import multiprocessing as mp
    q = mp.Queue()
    p = mp.Process(target=_worker_exec, args=(code, input_text, q))
    p.start()
    p.join(time_limit)
    if p.is_alive():
        p.terminate()
        p.join(0.1)
        return "timeout", "Tempo esgotado (possível loop infinito)"
    try:
        status, out = q.get_nowait()
    except Exception:
        status, out = ("exc", "Sem saída (erro desconhecido)")
    if isinstance(out, str) and len(out) > output_limit:
        out = out[:output_limit] + "\n... (truncado)"
    return status, out

def _headers():
    # usar a API "contents" com Accept raw => devolve o arquivo cru; Authorization se privado
    h = {"Accept": "application/vnd.github.raw"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h

def _url(pathname: str) -> str:
    """Monta URL baseando-se no GITHUB_RAW_BASE e branch."""
    base = (GITHUB_RAW_BASE or "").rstrip("/")
    sep = "&" if "?" in base else "?"
    return f"{base}/{pathname}{sep}ref={GITHUB_BRANCH}"

@st.cache_data(show_spinner=False, ttl=600)
def load_enunciados():
    url = _url("enunciados.json")
    r = requests.get(url, timeout=20, headers=_headers())
    r.raise_for_status()
    data = r.json()
    # normaliza chaves (ex1, ex2, …)
    return {str(k): v for k, v in data.items()}

@st.cache_data(show_spinner=False, ttl=600)
def load_tests(tag: str):
    """Prefere cN.json (com hash). Se não houver, tenta exN.json (sem hash)."""
    m = re.search(r"(\d+)", str(tag))
    n = m.group(1) if m else str(tag)
    urls = [_url(f"c{n}.json"), _url(f"ex{n}.json")]
    last_err = None
    for url in urls:
        try:
            r = requests.get(url, timeout=20, headers=_headers())
            r.raise_for_status()
            data = r.json()
            # cN.json tem: {"normalizacao":"...", "hash_alg":"sha256", "cases":[{"entrada","saida_hash"}]}
            # exN.json (fallback) tem: {"normalizacao":"...", "cases":[{"entrada","saida"}]}
            norm = data.get("normalizacao", "strip")
            hash_alg = data.get("hash_alg", None)
            cases = data.get("cases", data if isinstance(data, list) else [])
            return {"normalizacao": norm, "hash_alg": hash_alg, "cases": cases}
        except Exception as e:
            last_err = e
    raise last_err or RuntimeError("Não foi possível carregar os testes.")

# =========================
# Enunciados + chaves (carrega cedo p/ o painel ficar no topo)
# =========================
try:
    ENUNS = load_enunciados()
    ex_keys = sorted(ENUNS.keys(), key=lambda k: int(re.search(r"\d+", k).group(0)))
except Exception:
    ENUNS = {}
    # fallback genérico (ajusta a quantidade aqui se quiser)
    ex_keys = [f"ex{i}" for i in range(1, 13)]

# =========================
# Estado + painel (TOPO)
# =========================
if "codes" not in st.session_state:
    st.session_state["codes"] = {k: "" for k in ex_keys}
if "results" not in st.session_state:
    st.session_state["results"] = {}

def render_dashboard(ph):
    rows = []
    for k in ex_keys:
        ok, tot = st.session_state["results"].get(k, (0, 0))
        pct = round((ok/tot)*100, 1) if tot else ""
        status = "—" if tot==0 else ("✅" if ok==tot else ("🔴" if ok==0 else "🟡"))
        rows.append({"Exercício": k.upper(), "Acertos": f"{ok}/{tot}" if tot else "", "%": pct, "Status": status})
    with ph.container():
        st.subheader(f"📊 Seu progresso na {LISTA_ID}")
        st.dataframe(_pd.DataFrame(rows)[["Exercício","Acertos","%","Status"]],
                     hide_index=True, use_container_width=True)
        valid = [r for r in rows if r["%"] != ""]
        avg = sum(r["%"] for r in valid)/len(valid) if valid else 0.0
        st.progress(min(1.0, avg/100))
        st.caption(f"Progresso médio (nos avaliados): {avg:.1f}%")

dash = st.empty()
render_dashboard(dash)

# =========================
# UI principal
# =========================
st.title("Lista 2 — Pré-correção Automática (MPM.PPM.T2)")
st.markdown("Selecione o exercício, escreva seu código e rode os testes.")

ex = st.selectbox("Exercício", ex_keys, format_func=lambda k: k.upper())

# enunciado
if ENUNS.get(ex):
    st.markdown(ENUNS[ex])
else:
    st.info("Enunciado não encontrado no repositório (enunciados.json).")

# editor (Ace) com fallback
ACE_OK = False
try:
    from streamlit_ace import st_ace
    ACE_OK = True
except Exception:
    ACE_OK = False

if ACE_OK:
    code = st_ace(
        value=st.session_state["codes"].get(ex, ""),
        language="python",
        theme="chrome",
        keybinding="vscode",
        font_size=14,
        tab_size=4,
        wrap=True,
        show_gutter=True,
        show_print_margin=False,
        auto_update=True,
        placeholder="# Escreva seu código aqui (use input() e print())",
        height=340,
        key=f"ace_{ex}",
    )
    st.session_state["codes"][ex] = code or ""
else:
    code = st.text_area(
        "Seu código (use input() e print())",
        value=st.session_state["codes"].get(ex, ""),
        height=260,
        key=f"code_{ex}",
        placeholder="# Escreva seu código aqui (use input() e print())",
    )
    st.session_state["codes"][ex] = code or ""

col1, col2 = st.columns([1,1])
with col1:
    rodar = st.button("Rodar avaliação", type="primary")
with col2:
    if st.button("Limpar saída"):
        st.session_state["results"].pop(ex, None)
        render_dashboard(dash)

if rodar:
    with st.spinner("Carregando casos e executando..."):
        try:
            bundle = load_tests(ex)
            norm_mode = bundle["normalizacao"]
            hash_alg = bundle.get("hash_alg")
            casos = bundle["cases"]
            ok, total = 0, len(casos)
            code_to_run = st.session_state["codes"][ex]

            for i, caso in enumerate(casos, start=1):
                entrada = caso.get("entrada", "")
                status, out = run_user_code(code_to_run, entrada)

                if status == "exc":
                    st.error(f"Teste {i}: ERRO — {out}")
                    continue
                if status == "timeout":
                    st.error(f"Teste {i}: ERRO — {out}")
                    continue

                out_norm = _normalize(out, norm_mode)

                if hash_alg:  # cN.json
                    expected_hash = caso.get("saida_hash", "")
                    got_hash = _sha256(out_norm)
                    if got_hash == expected_hash:
                        ok += 1; st.success(f"Teste {i}: OK")
                    else:
                        st.warning(f"Teste {i}: ERRO")
                else:         # exN.json (fallback)
                    expected = _normalize(caso.get("saida", ""), norm_mode)
                    if out_norm == expected:
                        ok += 1; st.success(f"Teste {i}: OK")
                    else:
                        st.warning(f"Teste {i}: ERRO")

            st.info(f"*Resumo {ex.upper()}: {ok}/{total} OK*")
            st.session_state["results"][ex] = (ok, total)
            # atualiza painel do topo imediatamente
            render_dashboard(dash)

        except Exception as e:
            st.error(f"Falha ao carregar/rodar testes: {e}")
