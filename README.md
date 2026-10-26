# Potamus Security — atualizações e definições

Canal público de atualizações do plugin **Potamus Security** da [CodiPotamus](https://codipotamus.site).
Os sites com o plugin instalado descarregam daqui:

| Ficheiro | Para quê |
| --- | --- |
| `update.json` | Informação da versão mais recente, com a impressão digital e a assinatura do pacote. |
| `releases/potamus-security-X.Y.Z.zip` | Os pacotes de cada versão. |
| `definitions.json` | Definições de ameaças: padrões de código malicioso e plugins/temas com vulnerabilidades conhecidas. |

## Segurança

Todos os ficheiros são **assinados com Ed25519** pela CodiPotamus. O plugin traz a chave pública e
recusa qualquer ficheiro cuja assinatura não seja válida — um ficheiro alterado aqui, por engano ou
por um atacante, é simplesmente ignorado pelos sites. A chave privada nunca é publicada.

Os sites não enviam nenhuma informação para este repositório: apenas descarregam os ficheiros.
