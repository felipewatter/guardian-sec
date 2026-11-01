# Política de segurança — Guardian Sec

Para reportar vulnerabilidades, utilize os Security Advisories privados do GitHub quando disponíveis. Não publique segredos reais nem trechos sensíveis em issues.

## Modelo de segurança

A análise principal é **local e offline**. Não acessa a API GitHub, registros npm ou provedores externos. A exceção é a consulta **local** ao executável Git quando `--history` é solicitado.

- O scanner não imprime correspondências de credenciais, apenas `ruleId`, severidade, arquivo relativo e linha. Caminhos são saneados para caracteres de controle.
- São aplicados limites de arquivos, bytes por arquivo, bytes totais e profundidade; ultrapassá-los resulta em **exit 2** e não em falso relatório limpo.
- Links simbólicos explícitos são ignorados; arquivos são abertos com `O_NOFOLLOW` em sistemas Unix e verificação `fstat` para reduzir travessias inesperadas. Não elimina TOCTOU em diretórios mutáveis.
- Binários com byte NUL no início ou UTF-8 inválido são ignorados e contados.
- A varredura de histórico é opt-in e limitada aos últimos 30 commits enumerados por `git rev-list --all`. A saída Git tem limite e timeout; texto de patches não é incluído nos findings.
- Nenhum código do repositório-alvo é executado; manifests JSON e package-lock são analisados como dados.

## Limitações documentadas

- Detecção por regex é heurística, com falsos positivos e negativos. Segredos codificados, arquivos binários e diretórios ignorados não são analisados.
- A avaliação de CI/CD é textual e pode não compreender expressões YAML sofisticadas ou fluxos dinâmicos. Um workflow com um uso inseguro não significa exploração confirmada.
- A análise de dependências verifica **higiene de versão/lockfile**, sem obter advisories nem auditar os pacotes com CVEs. Consulte ferramentas SCA especializadas para esse fim.
- O SBOM é montado a partir do lockfile npm; não verifica pacotes realmente instalados nem a autenticidade dos artefatos.
- Histórico completo, todos os branches remotos e alterações não incluídas em 30 commits podem escapar à varredura.
- Não verifica branch protection, GitHub Security, Dependabot, permissões de colaboradores ou segurança remota: essas funções dependem de API/credenciais e **não estão implementadas**.
- Não promete segurança organizacional. O score é indicativo, somente para categorias aplicáveis e implementadas.
- Arquivos controlados por adversários podem ser modificados durante a análise; use snapshot somente leitura, ambiente isolado e privilégios mínimos.
- Os relatórios SARIF/Markdown e SBOM incluem **nomes de caminhos e pacotes** (não valores de segredos). Avalie a classificação desses metadados antes de publicar artefatos.
- Qualquer segredo real comprometido deve ser **revogado e rotacionado**.

## Código de saída

0 = sem achados acima do limiar; 1 = achados; 2 = auditoria falhou ou ficou incompleta. Não interprete exit 0 como garantia de segurança.
