const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'yourSecretKey'; // Use um segredo forte em produção

// Middleware
app.use(bodyParser.json()); // garante que o JSON seja lido corretamente
app.use(cors());

// Conexão com o banco de dados SQLite
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err.message);
  } else {
    console.log('Conectado ao banco de dados SQLite.');
  }
});

// Criação das tabelas se não existirem
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    plate TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

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

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao verificar usuário no banco.' });
    }
    if (user) {
      return res.status(400).json({ message: 'Usuário já existe.' });
    }

    db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, password], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Erro ao registrar usuário.' });
      }
      res.status(201).json({ message: 'Usuário registrado com sucesso!', userId: this.lastID });
    });
  });
});

// Rota de login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao verificar usuário no banco.' });
    }
    if (!user || user.password !== password) {
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    const token = generateToken(user);
    res.json({ message: 'Login bem-sucedido.', token });
  });
});

// Rota para obter informações do usuário
app.get('/api/users/:id', verifyToken, (req, res) => {
  const userId = req.params.id;

  if (userId != req.user.id) {
    return res.status(403).json({ message: 'Acesso negado.' });
  }

  db.get('SELECT id, name, email FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao buscar usuário.' });
    }
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }
    res.json(user);
  });
});

// Rota para atualizar informações do usuário
app.put('/api/users/:id', verifyToken, (req, res) => {
  const { name, email, password } = req.body;
  const userId = req.params.id;

  if (userId != req.user.id) {
    return res.status(403).json({ message: 'Acesso negado.' });
  }

  db.run('UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?', [name, email, password, userId], function (err) {
    if (err) {
      return res.status(500).json({ message: 'Erro ao atualizar usuário.' });
    }
    res.json({ message: 'Usuário atualizado com sucesso.' });
  });
});

// Rota para criar uma nova notificação
app.post('/api/notifications', verifyToken, (req, res) => {
  const { plate, occurrence } = req.body;

  if (!plate || !occurrence) {
    return res.status(400).json({ message: 'Placa e ocorrência são obrigatórios.' });
  }

  db.run('INSERT INTO notifications (user_id, plate, occurrence) VALUES (?, ?, ?)', [req.user.id, plate, occurrence], function (err) {
    if (err) {
      return res.status(500).json({ message: 'Erro ao criar notificação.' });
    }
    res.status(201).json({ message: 'Notificação criada com sucesso!', notificationId: this.lastID });
  });
});

// Rota para listar notificações enviadas pelo usuário
app.get('/api/notifications/sent', verifyToken, (req, res) => {
  db.all('SELECT * FROM notifications WHERE user_id = ?', [req.user.id], (err, notifications) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao listar notificações.' });
    }
    res.json(notifications);
  });
});

// Rota para listar notificações recebidas (simulando aqui com notificações de todos os usuários)
app.get('/api/notifications/received', verifyToken, (req, res) => {
  db.all('SELECT * FROM notifications WHERE user_id != ?', [req.user.id], (err, notifications) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao listar notificações recebidas.' });
    }
    res.json(notifications);
  });
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
