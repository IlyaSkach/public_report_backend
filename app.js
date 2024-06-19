const express = require("express");
const mysql = require("mysql");
const CONFIG = require("./config");
const cors = require("cors");
const session = require("express-session");
require('dotenv').config();
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const app = express();
const port = 3001;
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');


app.use(
  cors({
    origin: "https://main--bejewelled-toffee-9bccd9.netlify.app/",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// header
async function authenticateUser(req) {
  console.log("Функция authenticateUser вызвана");
  console.log("Заголовки запроса:", req.headers); 
  // Убедитесь, что заголовок Authorization существует и начинается с 'Bearer '
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    console.error("Заголовок Authorization отсутствует или неверный формат");
    return null;
  }

  // Извлекаем токен JWT из заголовка Authorization
  const token = req.headers.authorization.split(' ')[1];
  console.log("Полученный токен:", token);

  // Добавляем проверку на null или пустую строку для токена
  if (!token || token === 'null') {
    console.error("Токен не предоставлен или неверный");
    return null;
  }

  try {
    // Проверяем токен на валидность и извлекаем из него данные
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    console.log("dec",decoded);
    // Используем userId из токена для получения данных пользователя из БД
    const sql = "SELECT id, username, role FROM simplauth_users WHERE id = ?";
    const result = await queryDb(sql, [decoded.userId]); // Предполагаем, что в токене есть поле userId
    
    if (result.length > 0) {
      // Возвращаем данные пользователя, если он найден
      return result[0];
    } else {
      // Возвращаем null, если пользователь не найден
      return null;
    }
  } catch (error) {
    console.error("Ошибка при аутентификации пользователя:", error);
    // Обработка ошибок, связанных с JWT или запросом к БД
    return null;
  }
}

app.get("/api/user", async (req, res) => {
  // Предположим, у вас есть функция authenticateUser, которая проверяет, аутентифицирован ли пользователь
  const user = await authenticateUser(req);
  if (user) {
    // Если пользователь аутентифицирован, отправляем его данные
    res.json({
      id: user.id,
      username: user.username,
      role: user.role
      // Добавьте сюда любые другие данные пользователя, которые вам нужны
    });
  } else {
    // Если пользователь не аутентифицирован, отправляем ошибку
    res.status(401).json({ error: 'Пользователь не аутентифицирован' });
  }
});
// end

// Pass start

app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).send("Необходимо указать имя пользователя и пароль");
  }

  try {
    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQL запрос для добавления пользователя
    const sql =
      "INSERT INTO simplauth_users (username, password, role) VALUES (?, ?, ?)";

    // Вызов функции для выполнения запроса к БД
    await queryDb(sql, [username, hashedPassword, role]);

    res.send("Пользователь успешно зарегистрирован");
  } catch (err) {
    console.error(err);
    res.status(500).send("Ошибка сервера при регистрации");
  }
});
app.use(
  session({
    secret: "3cDf!9*#sGvP",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // Для HTTPS установите в true
  })
);

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM simplauth_users WHERE username = ?";
  try {
    const users = await queryDb(sql, [username]);
    if (users.length > 0) {
      const user = users[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        // Создаем токен
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
        // Отправляем токен в ответе
        res.json({ message: "Вы успешно вошли в систему!", token: token });
      } else {
        res.status(401).send("Неверный пароль");
      }
    } else {
      res.status(404).send("Пользователь не найден");
    }
  } catch (err) {
    res.status(500).send("Ошибка сервера");
  }
});

function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).send("Необходима аутентификация");
  }
}

// Используйте isAuthenticated как middleware для защищенных маршрутов
app.get("/protected-route", isAuthenticated, (req, res) => {
  res.send("Это защищенный маршрут");
});
// end 

function queryDb(query, params = []) {
  return new Promise((resolve, reject) => {
    const connection = mysql.createConnection(CONFIG);
    connection.connect((err) => {
      if (err) {
        console.error("Ошибка подключения к базе данных:", err);
        reject(err);
        return;
      }
    });

    connection.query(query, params, (err, result) => {
      connection.end();

      if (err) {
        console.error("Ошибка выполнения запроса к БД данных:", err);
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

app.get("/data/public_page", async (req, res) => {
  try {
    const result = await queryDb("SELECT * FROM public_page");
    res.json(result);
  } catch (err) {
    res.status(500).send("Error: " + err);
  }
});

app.get("/data/users", async (req, res) => {
  try {
    const result = await queryDb("SELECT * FROM simplauth_users");
    res.json(result);
  } catch (err) {
    res.status(500).send("Error: " + err);
  }
});

app.delete("/data/users/:userId", async (req, res) => {
  const userId = req.params.userId;
  try {
    const result = await queryDb("DELETE FROM simplauth_users WHERE id = ?", [userId]);
    if (result.affectedRows > 0) {
      res.send("Пользователь успешно удален");
    } else {
      res.status(404).send("Пользователь не найден");
    }
  } catch (err) {
    res.status(500).send("Ошибка при удалении пользователя: " + err);
  }
});

app.post("/addData", async (req, res) => {
  const { link, purchase_date, price, external_id } = req.body;
  const sql =
    "INSERT INTO public_page (link, purchase_date, price, external_id) VALUES (?, ?, ?, ?)";
  try {
    const result = await queryDb(sql, [link, purchase_date, price, external_id]);
    res.json("Data added to database");
  } catch (err) {
    res.status(500).send("ErrorM: " + err.message);
  }
});

app.post("/addMunual", async (req, res) => {
  const { name, amount, entry_date } = req.body;
  const sql =
    "INSERT INTO munual_entries (name, amount, entry_date) VALUES (?, ?, ?)";
  try {
    const result = await queryDb(sql, [name, amount, entry_date]);
    res.json("Data added to database");
  } catch (err) {
    res.status(500).send("ErrorM: " + err.message);
  }
});

app.get("/socialNames", async (req, res) => {
  try {
    const result = await queryDb("SELECT name FROM social_name");
    res.json(result);
  } catch (err) {
    res.status(500).send("Ошибка: " + err.message);
  }
});

// app.listen(port, () => {
//   console.log(`Server is running at http://localhost:${port}`);
// });

// Функция для проверки подключения к базе данных
function checkDatabaseConnection() {
  return new Promise((resolve, reject) => {
    const connection = mysql.createConnection({
      host: '95.31.212.54',
      port: '23031',
      user: 'user',
      password: 'au--Tw3fyP@JjI3x',
      database: 'social_stat',
    });

    connection.connect(err => {
      if (err) {
        console.error('Ошибка подключения к базе данных:', err);
        reject(err);
        return;
      }
      console.log('Успешное подключение к базе данных');
      connection.end();
      resolve();
    });
  });
}

// Проверяем подключение к БД перед запуском сервера
checkDatabaseConnection()
  .then(() => {
    app.listen(port, () => {
      console.log(`Server is running at http://localhost:${port}`);
    });
  })
  .catch(err => {
    console.error('Не удалось подключиться к базе данных, сервер не запущен.');
  });
