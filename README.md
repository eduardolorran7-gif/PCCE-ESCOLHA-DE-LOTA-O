# PCCE — Escolha de Lotação

Projeto com front-end + back-end local.

## Requisitos
- Node.js 22.5 ou superior.

## Executar
```bash
npm start
```

Depois acesse `http://localhost:3000`.

## Regras implementadas
- Cada matrícula pode registrar somente uma escolha.
- A unicidade é garantida pelo banco SQLite (`UNIQUE`), não apenas pelo JavaScript.
- Cada registro ocupa uma escolha para uma cidade.
- O TOP 10 é calculado no servidor por quantidade de escolhas.
- Em empate, as cidades são ordenadas alfabeticamente.
- O ranking é atualizado após um novo registro e também a cada 30 segundos.

## Arquivos
- `index.html`: mapa e interface.
- `server.js`: API HTTP.
- `lotacao.sqlite`: criado automaticamente na primeira execução.

## API
- `POST /api/escolhas` — body JSON: `{"matricula":"12345","cidade":"Fortaleza"}`
- `GET /api/ranking` — retorna TOP 10 e total de escolhas.

## Produção
Para publicar na internet, execute este projeto em um servidor com Node.js e armazenamento persistente para o arquivo SQLite. Em uma implantação com múltiplas instâncias, prefira PostgreSQL/MySQL em vez de SQLite.

## Novos recursos
- `PASSO A PASSO`: aviso de caráter não oficial e instruções de uso.
- `VER TODAS AS ESCOLHAS`: ranking completo por quantidade de escolhas.
- `GET /api/ranking-completo`



## Área administrativa

Acesse `/admin`. A senha não fica no HTML; configure a variável de ambiente `ADMIN_PASSWORD`.

### Windows CMD
```bat
set ADMIN_PASSWORD=Escolha-Uma-Senha-Forte
node --experimental-sqlite server.js
```

### PowerShell
```powershell
$env:ADMIN_PASSWORD="Escolha-Uma-Senha-Forte"
node --experimental-sqlite server.js
```

Depois abra:
`http://localhost:3000/admin`

Recursos:
- total de escolhas e cidades;
- tabela com matrícula, cidade e data/hora;
- pesquisa por matrícula ou cidade;
- exclusão administrativa de registro;
- exportação direta para `.xlsx`.

Ao excluir um registro, aquela matrícula volta a poder registrar uma escolha.


## Produção no Railway

O projeto detecta automaticamente `RAILWAY_VOLUME_MOUNT_PATH` e grava `lotacao.sqlite`
dentro do Volume. Não é necessário definir `DB_PATH` no Railway se o Volume estiver anexado.

Variáveis recomendadas no Railway:
- `ADMIN_PASSWORD`: senha forte e exclusiva (configure diretamente no Railway; não salve no GitHub).
- `NODE_ENV=production`

Volume:
- anexe um Volume ao serviço;
- use o mount path `/data`.

Segurança da área administrativa:
- cookie de sessão `HttpOnly`, `SameSite=Strict` e `Secure` em produção;
- limite de 8 tentativas de login por IP a cada 15 minutos;
- cabeçalhos básicos de segurança;
- senha somente por variável de ambiente.

O arquivo `.gitignore` impede o envio acidental de `.env` e bancos SQLite ao GitHub.
