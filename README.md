# Guardian Sec — Repository Security Posture

[![CI](https://github.com/felipewatter/guardian-sec/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/guardian-sec/actions/workflows/ci.yml)

Ferramenta **offline** em Node.js/TypeScript para verificações locais de postura de segurança em repositórios. A versão **2.1.0** substitui promessas não implementadas da documentação antiga por verificações reais, relatórios auditáveis e escopo claramente identificado.

## Capacidades implementadas

- **Segredos:** detecta padrões de AWS, GitHub, Stripe, Google, PEM e configurações com valores potencialmente sensíveis. Registra apenas a regra, o caminho e a linha; **nunca o segredo encontrado**.
- **Dependências:** identifica projetos npm sem lockfile, referências de pacotes fora do registry e versões como `*` e `latest`. **Não pesquisa CVEs nem valida advisories remotamente**.
- **CI/CD:** identifica ações GitHub não fixadas a SHA completo, workflows com permissões amplas e acionadores privilegiados. Faz inspeção estática de texto, não interpretação integral do YAML.
- **Histórico Git opcional:** `--history` inspeciona patches adicionados nos últimos **30 commits alcançáveis pelas referências locais**. Não inspeciona histórico completo.
- **SBOM CycloneDX 1.5:** `sbom` gera lista de componentes npm a partir de `package-lock.json`, sem download de pacotes ou consultas remotas.
- **Relatórios:** texto, JSON, Markdown e SARIF para integração com CI/CD. O score ponderado 0–100 reflete **somente as categorias implementadas e aplicáveis**; categorias não verificadas são identificadas no relatório.

O software **não avalia automaticamente políticas de proteção de branches, configurações remotas de Dependabot ou alertas privados da API GitHub**. Não promete um score DevSecOps universal e não envia dados para serviços externos.

## Requisitos

Node.js 22 ou 24 e npm. Para `--history`, requer Git instalado e um repositório Git local. Não há dependências runtime externas.

## Instalação

```bash
git clone https://github.com/felipewatter/guardian-sec.git
cd guardian-sec
npm install
npm run build
node dist/cli.js --help
```

Instalação global opcional do checkout compilado: `npm install -g .`. **Não há confirmação de publicação da versão 2.1.0 no registro npm.**

## Auditoria do diretório atual

```bash
node dist/cli.js scan . --format json
node dist/cli.js scan . --format md --output ./guardian-report.md
node dist/cli.js scan . --format sarif --output ./guardian-report.sarif
node dist/cli.js scan . --history --fail-on high
```

O scanner ignora `.git`, `node_modules`, `dist`, `coverage`, binários reconhecidos e links simbólicos. Arquivos acima do limite geram **erro operacional 2**, e não resultado limpo. O histórico é desativado por padrão e executado apenas mediante escolha explícita.

## Gerar SBOM

```bash
node dist/cli.js sbom . --output ./guardian.sbom.json
```

Gera objeto JSON compatível com CycloneDX 1.5 baseado nos pacotes npm registrados em `package-lock.json`. Se não encontrar lockfile válido, a execução falha. A SBOM não é uma prova de integridade ou de ausência de vulnerabilidades.

## Opções

| Opção | Padrão | Significado |
|---|---|---|
| `--format text\|json\|md\|sarif` | text | Formato do relatório scan |
| `--history` | off | Consulta opcional e limitada dos últimos 30 commits |
| `--output ARQUIVO` | stdout | Cria novo arquivo, sem sobrescrever |
| `--fail-on none\|low\|medium\|high\|critical` | high | Limiar para código de saída 1 |
| `--max-files` | 10000 | Limite de 30 mil arquivos |
| `--max-file-bytes` | 1048576 | Máximo 4 MiB por arquivo |
| `--max-total-bytes` | 33554432 | Máximo 128 MiB no total |
| `--max-depth` | 24 | Máximo 48 níveis |

**Códigos de saída:** 0 = sem achados no limiar configurado; 1 = achados no limiar; 2 = falha ou verificação incompleta. Podem existir achados menos severos mesmo com saída 0.

## Interpretação da pontuação

O score usa pesos **50** para segredos, **25** para dependências, **25** para CI/CD e **20** para histórico, se habilitado. Categorias sem arquivos pertinentes são `not_applicable`; o histórico desativado é `not_checked`, ambos excluídos do denominador. O indicador reflete apenas essas verificações e **não equivale a garantia de segurança**.

## Testes e segurança

```bash
npm run typecheck
npm test
npm pack --dry-run
```

O GitHub Actions executa testes com Node 22/24 em Ubuntu, Windows e macOS e audita as dependências da ferramenta.

Leia [SECURITY.md](SECURITY.md) para limitações, detecção heurística, proteção contra condições de corrida e privacidade.
