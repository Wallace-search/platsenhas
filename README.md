# Password Security Platform

A secure platform for managing passwords with departmental access and keyword-based decryption.

## Features

- User registration and login per department
- Encrypted storage of client and application passwords
- Keyword-based access to decrypt passwords

## Installation

1. Install dependencies: `npm install`
2. Copy `.env.example` to `.env` and fill in your values
3. Start MongoDB (local or cloud like MongoDB Atlas)
4. Run the server: `npm start`

## Deployment

For online deployment:

1. Set up MongoDB Atlas or another cloud MongoDB service
2. Update `MONGODB_URI` in environment variables
3. Set `JWT_SECRET` to a strong secret
4. Deploy to Heroku, AWS, or similar:
   - For Heroku: `heroku create`, `git push heroku main`, set env vars with `heroku config:set`

## Usage

- Register users with department
- Login to get JWT token
- Add passwords with type, name, password, keyword
- Retrieve passwords list (somente departamento do usuário)
- Access specific password by providing keyword

## Admin

- Administrador vê /admin/users, /admin/passwords, /admin/audit
- Painel admin na UI aparece só para role=admin

## Auditoria

- Logs em `AuditLog`: usuário, operação, target, timestamp, IP
- Registra acessos bem-sucedidos e falhos, criação de senhas

## Security Notes

- Passwords are encrypted using AES-256-CBC
- Keywords are hashed with bcrypt
- Use strong keywords and keep them secure