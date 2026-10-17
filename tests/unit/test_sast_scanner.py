from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.scanners.sast.engine import SASTEngine


def test_sast_detects_eval_and_exec_rce() -> None:
    """Comprova detecção de chamadas diretas a eval() e exec() (CWE-95)."""
    vulnerable_code = """
def calculate_user_formula(formula: str):
    return eval(formula)

def run_dynamic_plugin(code_str: str):
    exec(code_str)
"""
    engine = SASTEngine()
    findings = engine.scan_code(vulnerable_code, file_path="calc.py")

    assert len(findings) == 2
    assert all(f.category == ScannerCategory.SAST for f in findings)
    assert all(f.severity == SeverityLevel.CRITICAL for f in findings)
    assert findings[0].line_number == 3
    assert findings[1].line_number == 6


def test_sast_detects_command_injection_and_allows_safe_subprocess() -> None:
    """
    Comprova que:
    - os.system(...) e subprocess.run(..., shell=True) são detectados.
    - subprocess.run(["git", "status"], shell=False) NÃO gera falso positivo!
    """
    code = """
import os
import subprocess

def bad_ping(host: str):
    os.system(f"ping -c 1 {host}")
    subprocess.run(f"nslookup {host}", shell=True)

def good_ping(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
"""
    engine = SASTEngine()
    findings = engine.scan_code(code, file_path="network.py")

    assert len(findings) == 2
    lines = [f.line_number for f in findings]
    assert lines == [6, 7]
    assert any("SAST-CMD-001" in f.title for f in findings)
    assert any("SAST-CMD-002" in f.title for f in findings)


def test_sast_detects_sql_injection_via_fstring_and_concat() -> None:
    """
    Comprova detecção de SQL Injection via f-string e concatenação '+',
    ignorando queries parametrizadas seguras.
    """
    code = """
def get_user_unsafe(cursor, username: str):
    cursor.execute(f"SELECT id, email FROM users WHERE username = '{username}'")
    query = "DELETE FROM users WHERE id = " + username
    cursor.execute(query)

def get_user_safe(cursor, username: str):
    cursor.execute("SELECT id, email FROM users WHERE username = :u", {"u": username})
"""
    engine = SASTEngine()
    findings = engine.scan_code(code, file_path="repo.py")

    assert len(findings) == 2
    assert all("SAST-SQLI-001" in f.title for f in findings)
    assert [f.line_number for f in findings] == [3, 4]


def test_sast_detects_unsafe_deserialization_and_weak_crypto() -> None:
    """Comprova detecção de pickle.loads, yaml.load sem SafeLoader e hashlib.md5."""
    code = """
import hashlib
import pickle
import yaml

def parse_payload(raw_bytes: bytes, yaml_str: str):
    obj = pickle.loads(raw_bytes)
    cfg = yaml.load(yaml_str)
    safe_cfg = yaml.load(yaml_str, Loader=yaml.SafeLoader)
    digest = hashlib.md5(raw_bytes).hexdigest()
    return obj, cfg, safe_cfg, digest
"""
    engine = SASTEngine()
    findings = engine.scan_code(code, file_path="parser.py")

    assert len(findings) == 3
    titles = [f.title for f in findings]
    assert any("SAST-DESER-001" in t for t in titles)
    assert any("SAST-DESER-002" in t for t in titles)
    assert any("SAST-CRYPTO-001" in t for t in titles)


def test_sast_ast_ignores_comments_and_docstrings() -> None:
    """
    Comprova a superioridade da AST sobre Regex:
    Menções a eval(), os.system() ou SELECT dentro de strings comuns/comentários
    NÃO disparam falsos positivos!
    """
    safe_code = '''
# Nunca use eval(user_input) ou os.system("rm -rf /")
"""
Documentação: evite subprocess.run(cmd, shell=True) e pickle.loads(data).
"""
MESSAGE = "A função eval() foi removida por segurança."
'''
    engine = SASTEngine()
    findings = engine.scan_code(safe_code, file_path="docs.py")
    assert findings == []
