# Base Socorro

Cadastro de eleitores por coordenador. Cada coordenador entra só com a **matrícula**, sem criar conta.

- `/` cadastro e meta de votos garantidos
- `/lista` lista com busca e filtros por compromisso e bairro
- `/admin` coordenadores (gerar e desativar matrículas) e lista de bairros, só para o administrador

Cada coordenador vê e altera apenas os próprios cadastros. O administrador vê todos.

## Publicar de graça

### 1. Banco de dados (Neon)
1. Crie uma conta em https://neon.tech e um projeto novo (região mais próxima: São Paulo, se houver).
2. Copie a **connection string** (começa com `postgresql://...`).

O Postgres gratuito do Render expira em 30 dias, por isso o banco fica no Neon.

### 2. Código (GitHub)
Suba esta pasta para um repositório **privado** no GitHub.

### 3. Servidor (Render)
1. Em https://render.com, clique em **New → Web Service** e escolha o repositório.
2. Build command: `npm install` · Start command: `npm start` · Plano: **Free**.
3. Em **Environment**, adicione:

| Variável | Valor |
|---|---|
| `DATABASE_URL` | a connection string do Neon |
| `ADMIN_MATRICULA` | sua matrícula de administrador (8+ letras e números, difícil de adivinhar) |
| `SESSION_SECRET` | um texto longo e aleatório (40+ caracteres) |
| `NODE_ENV` | `production` |

4. Clique em **Deploy**. As tabelas são criadas sozinhas na primeira vez.

Ou use o arquivo `render.yaml` (Blueprint) e preencha as variáveis quando o Render pedir.

## Usar
1. Abra o endereço do Render e entre com a `ADMIN_MATRICULA`.
2. Em **Admin**, gere uma matrícula para cada coordenador e envie para ele.
3. Para cortar o acesso de alguém, toque em **Desativar**.

## Observações
- No plano grátis, o servidor dorme após 15 minutos sem uso. O primeiro acesso depois disso leva cerca de 1 minuto.
- O login dura 12 horas.
- Rodar no computador: `npm install`, defina as variáveis e `npm start` (porta 3000).
