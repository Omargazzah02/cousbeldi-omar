// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données: ', err);
    process.exit(1);
  }
  console.log('Connexion à MySQL réussie');
});

app.post('/register', async (req, res) => {
  const { email, password, phone_number, address, additional_address, city, zip_code } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'L\'email et le mot de passe sont requis.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'L\'email est invalide.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Le mot de passe doit contenir au moins 6 caractères.' });
  }

  const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailQuery, [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Erreur lors de la vérification de l\'email.' });
    }
    if (results.length > 0) {
      return res.status(400).json({ message: 'L\'email est déjà utilisé.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO users (email, password, phone_number, address, additional_address, city, zip_code)
      VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.query(query, [email, hashedPassword, phone_number, address, additional_address, city, zip_code], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Erreur lors de l\'inscription de l\'utilisateur.' });
      }

      const token = jwt.sign(
        { userId: result.insertId, email: email }, // Payload avec l'ID de l'utilisateur et son email
        process.env.JWT_SECRET,                    // Secret pour signer le JWT
        { expiresIn: process.env.JWT_EXPIRATION }  // Durée de validité du token
      );

      res.status(200).json({ message: 'Utilisateur créé avec succès.', token });
    });
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'L\'email et le mot de passe sont requis.' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ message: 'Email ou mot de passe incorrect.' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Email ou mot de passe incorrect.' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION }
    );

    res.json({ message: 'Connexion réussie', token });
  });
});

app.get('/protected', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ message: 'Aucun token fourni.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token invalide.' });
    }

    res.json({ message: 'Accès autorisé', user: decoded });
  });
});























// Fonction pour vérifier le token JWT
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extraire le token du header
  
    if (!token) {
      return res.status(403).json({ message: 'Aucun token fourni.' });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Token invalide.' });
      }
  
      req.user = decoded; // Ajoute l'utilisateur décodé à la requête pour un usage ultérieur
      next(); // Passer à la prochaine fonction ou route
    });
  }
  
  // Route protégée : "bonjour"
  app.get('/test', verifyToken, (req, res) => {
    res.json({ message: `Bonjour, ${req.user.email}!` });
  });
  
  // Exemple de route pour tester la protection
  app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'Accès autorisé', user: req.user });
  });
  



// Démarrage du serveur
const port = 3000;
app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
