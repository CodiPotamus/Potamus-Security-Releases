# Potamus Security — atualizações e definições

Canal público de atualizações do plugin **Potamus Security** da [CodiPotamus](https://codipotamus.site).
Os sites com o plugin instalado descarregam daqui:

| Ficheiro | Para quê |
| --- | --- |
| `update.json` | Informação da versão mais recente, com a impressão digital e a assinatura do pacote. |
| `releases/potamus-security-X.Y.Z.zip` | Os pacotes de cada versão. |
| `definitions.json` | Radar de Ameaças: padrões de código malicioso e plugins/temas com vulnerabilidades conhecidas. Atualizado todas as segundas-feiras a partir de fontes públicas: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CC0) e [NVD](https://nvd.nist.gov). |
| `radar/state.json` | Dados recolhidos (não assinados) que dão origem ao `definitions.json`. |

## Segurança

Todos os ficheiros são **assinados com Ed25519** pela CodiPotamus. As versões do plugin usam a chave de código, que nunca está no GitHub; o Radar de Ameaças é assinado aqui, automaticamente, com uma chave própria que o plugin só aceita para a lista de ameaças. O plugin traz a chave pública e
recusa qualquer ficheiro cuja assinatura não seja válida — um ficheiro alterado aqui, por engano ou
por um atacante, é simplesmente ignorado pelos sites. A chave privada nunca é publicada.

Os sites não enviam nenhuma informação para este repositório: apenas descarregam os ficheiros.

This product uses the NVD API but is not endorsed or certified by the NVD.
