const express = require('express');
const Database = require('better-sqlite3'); // Mudança de sqlite3 para better-sqlite3
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'yourSecretKey'; // Use um segredo forte em produção

// Middleware
app.use(bodyParser.json()); // garante que o JSON seja lido corretamente
app.use(cors());

// Conexão com o banco de dados SQLite usando better-sqlite3
const db = new Database('./database.db', { verbose: console.log });

console.log('Conectado ao banco de dados SQLite.');

// Criação das tabelas se não existirem
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    plate TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`).run();

// Função para gerar token JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.id, name: user.name }, SECRET_KEY, { expiresIn: '1h' });
};

// Middleware para verificar o token JWT
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(403).json({ message: 'Acesso negado.' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido.' });
    }
    req.user = decoded;
    next();
  });
};

// Rota de registro de usuário
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Nome, e-mail e senha são obrigatórios.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user) {
    return res.status(400).json({ message: 'Usuário já existe.' });
  }

  const stmt = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
  const result = stmt.run(name, email, password);
  res.status(201).json({ message: 'Usuário registrado com sucesso!', userId: result.lastInsertRowid });
});

// Rota de login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || user.password !== password) {
    return res.status(400).json({ message: 'Credenciais inválidas.' });
  }

  const token = generateToken(user);
  res.json({ message: 'Login bem-sucedido.', token });
});

// Rota para obter informações do usuário
app.get('/api/users/:id', verifyToken, (req, res) => {
  const userId = req.params.id;

  if (userId != req.user.id) {
    return res.status(403).json({ message: 'Acesso negado.' });
  }

  const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(userId);
  if (!user) {
    return res.status(404).json({ message: 'Usuário não encontrado.' });
  }
  res.json(user);
});

// Rota para atualizar informações do usuário
app.put('/api/users/:id', verifyToken, (req, res) => {
  const { name, email, password } = req.body;
  const userId = req.params.id;

  if (userId != req.user.id) {
    return res.status(403).json({ message: 'Acesso negado.' });
  }

  const stmt = db.prepare('UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?');
  stmt.run(name, email, password, userId);
  res.json({ message: 'Usuário atualizado com sucesso.' });
});

// Rota para criar uma nova notificação
app.post('/api/notifications', verifyToken, (req, res) => {
  const { plate, occurrence } = req.body;

  if (!plate || !occurrence) {
    return res.status(400).json({ message: 'Placa e ocorrência são obrigatórios.' });
  }

  const stmt = db.prepare('INSERT INTO notifications (user_id, plate, occurrence) VALUES (?, ?, ?)');
  const result = stmt.run(req.user.id, plate, occurrence);
  res.status(201).json({ message: 'Notificação criada com sucesso!', notificationId: result.lastInsertRowid });
});

// Rota para listar notificações enviadas pelo usuário
app.get('/api/notifications/sent', verifyToken, (req, res) => {
  const notifications = db.prepare('SELECT * FROM notifications WHERE user_id = ?').all(req.user.id);
  res.json(notifications);
});

// Rota para listar notificações recebidas (simulando aqui com notificações de todos os usuários)
app.get('/api/notifications/received', verifyToken, (req, res) => {
  const notifications = db.prepare('SELECT * FROM notifications WHERE user_id != ?').all(req.user.id);
  res.json(notifications);
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
