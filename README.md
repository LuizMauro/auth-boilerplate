# Auth Boilerplate d

## Visão Geral

Este é um boilerplate de autenticação desenvolvido em NestJS e PostgreSQL, que fornece funcionalidades para autenticação, autorização e segurança dos usuários.

## Funcionalidades Disponíveis

### 1. Cadastro de Usuário

- Permite que novos usuários se registrem fornecendo nome, email e senha.
- As senhas são armazenadas de forma segura utilizando bcrypt.

### 2. Login com JWT

- Autenticação usando JSON Web Tokens (JWT).
- O usuário recebe um token JWT após um login bem-sucedido, que pode ser usado para acessar recursos protegidos.

### 3. Redefinição de Senha

### 3.1 Via Email

- Permite que os usuários solicitem a redefinição de senha enviando um email de verificação.
- Um token de redefinição é gerado e enviado ao email do usuário, com um link para definir uma nova senha.
- O link de redefinição de senha expira após 10 minutos.

### 3.2 Via OTP (One-Time Password)

- Permite que os usuários solicitem um código OTP enviado ao email registrado
- O usuário deve inserir o OTP junto com uma nova senha para redefinir a senha da conta.
- O OTP tem validade de 10 minutos e é invalidado após ser usado.

### 4. Proteção de Rotas e Controle de Acesso

- Rotas protegidas por JwtAuthGuard para garantir que apenas usuários autenticados possam acessá-las.
- RolesGuard para controle de permissões baseado em papéis (como ‘admin’, ‘user’, etc.), permitindo um controle de acesso mais granular.

### 5. Rate Limiting (Limitação de Requisições)

- Utiliza ThrottlerModule para limitar o número de requisições em um período de tempo.
- Protege endpoints críticos, como login, contra ataques de força bruta.

### 6. Notificações de Segurança

- **Tentativas Falhas de Login:** O usuário é notificado por email após 5 tentativas falhas de login.
- **Alteração de Senha:** Notificação de confirmação enviada ao email do usuário quando a senha é alterada.

### 7. Registro de Tentativas Falhas no Banco de Dados

- As tentativas falhas de login são armazenadas no banco de dados, com um contador para cada usuário e o registro do tempo da última tentativa.
- Após um período de 5 minutos sem novas tentativas, o contador é resetado.

### 8. Estratégia de Autenticação com OAuth (em progresso)

- Integração planejada com provedores externos de login, como Google, Facebook e GitHub.
- Facilita o login dos usuários utilizando credenciais que eles já possuem.

## Como Executar o Projeto

### Requisitos

- Node.js (v14 ou superior)
- PostgreSQL
- NestJS CLI (opcional, para desenvolvimento)

### Instalação

1. Clone o repositório:

   ```bash
   git clone https://github.com/LuizMauro/auth-boilerplate
   ```

2. Instale as dependências::

```bash
 npm install
```

3. Crie um arquivo `.env` com as seguintes variáveis:

```bash
  JWT_SECRET=your_secret_key
  # DB CONFIG
  DB_HOST=localhost
  DB_PORT=5432
  DB_USERNAME=your_username
  DB_PASSWORD=your_password
  DB_NAME=your_database
  # EMAIL CONFIG
  EMAIL_USER=your_username
  EMAIL_PASS="your_password"
  EMAIL_HOST=localhost
  EMAIL_PORT=2525
  # RATE LIMITNG
  RATE_LIMITING_LIMIT=10
  RATE_LIMITING_TTL=60
  # Login Attempts
  FAILED_LOGIN_ATTEMPTS=5
  # FRONTEND
  FRONTEND_URL=http://localhost:3000
```

### Executando a Aplicação

- Execute o projeto em ambiente de desenvolvimento:

```bash
  npm run start:dev
```

### Documentação da API

- **Swagger**: A documentação interativa da API está disponível através do Swagger na rota `/docs`.

### Melhorias Planejadas

- **Login Social**: Integração com OAuth para login via Google, Facebook e GitHub.
- **Login de Novo Dispositivo:** O usuário recebe um alerta sempre que um login é realizado de um dispositivo desconhecido.

### Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests para melhorias ou correções.

### Licença

Este projeto está licenciado sob a Licença MIT.
