# Usage: python3 scripts/gen_eviction_cases.py vendor/bitcoin/src/test/net_peer_eviction_tests.cpp
# Prints the protection cases used in test/exnode/p2p/eviction_test.exs.
# Converts Core's peer_protection_test IsProtected(...) cases into Elixir data.
import re, sys
src = open(sys.argv[1]).read()
body = src[src.index('BOOST_AUTO_TEST_CASE(peer_protection_test)'):src.index('// Returns true if any of the node ids')]
body = re.sub(r'//[^\n]*', '', body)
calls = re.findall(r'IsProtected\(\s*(.*?)random_context\)\);', body, re.S)
fields = {'m_connected': 'connected', 'm_is_local': 'is_local', 'm_network': 'network'}
def expr(e):
    e = e.strip()
    e = re.sub(r'NodeSeconds\{std::chrono::seconds\{(.*?)\}\}', r'\1', e)
    e = re.sub(r'NET_(\w+)', lambda m: ':' + m.group(1).lower(), e)
    e = e.replace('||', ' or ').replace('&&', ' and ')
    m = re.match(r'^\((.*)\)\s*\?\s*(\S+)\s*:\s*(\S+)$', e)
    if m: return f'if({expr(m.group(1))}, do: {m.group(2)}, else: {m.group(3)})'
    return re.sub(r'\s+', ' ', e)
def stmts(b):
    out = []
    b = b.strip()
    while b:
        if b.startswith('if'):
            # if (...) { a } else if (...) { b } ... else { c }
            m = re.match(r'(if\s*\(.*?\)\s*\{.*?\}(?:\s*else\s+if\s*\(.*?\)\s*\{.*?\})*\s*else\s*\{.*?\})', b, re.S)
            chain = m.group(1); b = b[m.end():].strip()
            arms = re.findall(r'(?:if\s*\((.*?)\)|else)\s*\{\s*c\.m_network\s*=\s*(\S+?);\s*\}', chain, re.S)
            conds = [(expr(c) if c else 'true', expr(v)) for c, v in arms]
            out.append('c = %{c | network: cond do ' + '; '.join(f'{c} -> {v}' for c, v in conds) + ' end}')
        else:
            m = re.match(r'c\.(\w+)\s*=\s*(.*?);', b, re.S)
            out.append(f'c = %{{c | {fields[m.group(1)]}: {expr(m.group(2))}}}')
            b = b[m.end():].strip()
    return out
print('  defp protection_cases do\n    [')
for call in calls:
    m = re.match(r'(\w+|\d+),\s*\[[^\]]*\]\(NodeEvictionCandidate& c\)\s*\{(.*)\},\s*/\*protected_peer_ids=\*/\{(.*?)\},\s*/\*unprotected_peer_ids=\*/\{(.*?)\},\s*$', call.strip(), re.S)
    n, b, prot, unprot = m.groups()
    n = '12' if n == 'num_peers' else n
    body_ex = '; '.join(stmts(b.replace('num_peers', 'n')))
    print(f'    {{{n}, fn c, n -> _ = n; {body_ex}; c end, [{prot}], [{unprot}]}},')
print('    ]\n  end')
