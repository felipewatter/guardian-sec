# Changelog

## 2.1.0 — 2026-10-31

- Substituída CLI que executava uma única checagem por motor de postura com verificações locais reais de segredos, dependências e workflows GitHub.
- Detecção de segredos sem expor valores, limites de leitura e proteção para links simbólicos.
- Scanner opcional de histórico Git limitado a 30 commits, com stdout/timeout limitados.
- Geração de SBOM CycloneDX 1.5 para dependências npm identificadas em package-lock.json.
- Relatórios em texto, JSON, Markdown e SARIF 2.1.0 com regra e localização, sem snippet de segredo.
- Pontuação por categorias efetivamente examinadas, com estado not_applicable/not_checked explícito.
- CLI com threshold configurável, limites operacionais, arquivo de saída de criação exclusiva e exit 0/1/2.
- Atualizados requisitos Node.js, testes automatizados, GitHub Actions multiplataforma e documentação de escopo/segurança.
- Removidas promessas de integração remota Github, plugins arbitrários e análise de CVEs não implementadas.

## 2.0.0

- Protótipo inicial de varredura de segredos locais com documentação aspiracional.
