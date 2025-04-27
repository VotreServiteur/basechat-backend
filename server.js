require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3001;

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const jwtSecret = process.env.JWT_SECRET || 'testingsecretkey';

const cors = require('cors');

const corsOptions = {
    origin: 'http://localhost:3000',
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ success: false, message: 'Authentication token required/' });
    }


    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid token'
            });
        }

        req.user = user;
        next();
    });
}


app.post('/api/auth/register', async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({
            success: false,
            message: 'Login and password are required.'
        });
    }

    try {
        const userExists = await pool.query(
            'SELECT 1 FROM users WHERE login = $1',
            [login]);

        if (userExists.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Login already exists'
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (login, password) VALUES ($1, $2) RETURNING id, login',
            [login, hashedPassword]
        );

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: newUser.rows[0]
        });
    } catch (err) {
        console.error('Error during registration:', err.stack);
        res.status(500).json({
            success: false,
            message: 'Registration failed'
        })
    }

})

app.post('/api/auth/login', async (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) {
        return res.status(400).json({
            success: false,
            message: 'Login and password are required.'
        });
    }

    try {
        const userResult = await pool.query(
            'SELECT * FROM users WHERE login = $1',
            [login]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid login or password.'
            })
        }

        const user = userResult.rows[0];

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid login or password.'
            })
        }

        const token = jwt.sign(
            { userId: user.id, login: user.login },
            jwtSecret,
            { expiresIn: '1h' }
        )

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                login: user.login
            }
        });

    } catch (err) {
        console.error('Error during login:', err.stack);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
})

app.get(
    '/api/messages',
    authenticateToken,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    m.id,
                    m.text,
                    m.sender_id,
                    u.login as sender_login,
                    m.created_at
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                ORDER BY m.created_at ASC
                `);

            res.status(200).json(result.rows);

        } catch (err) {
            console.error('Error fetching messages:', err.stack);
            res.status(500).json({ success: false, message: 'Failed to fetch messages' });

        }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
    const senderId = req.user.userId;
    const { text } = req.body;

    if (!text || text.trim().length === 0){
        return res.status(400).json({ success: false, message: 'message text can not be empty'});
    }
    const chatId = 1;
    recieving

    try {
        const result = await pool.query(
            'INSERT INTO messages (chat_id, sender_id, text) VALUES ($1,$2,$3) RETURNING id, chat_id, sender_id, text, created_at',
            [chatId, senderId, text]
        );
        const newMessage = result.rows[0];

        const senderResult = await pool.query('SELECT login FROM users WHERE id = $1', [senderId]);
        const senderLogin = senderResult.rows[0].login;

        res.status(201).json({
            success: true,
            message: 'Message sent successfully',
            messageData: {
                id: newMessage.id,
                chat_id: newMessage.chat_id,
                sender_id: newMessage.sender_id,
                text: newMessage.text,
                created_at: newMessage.created_at,
                sender_login: senderLogin
            }
        })

    }catch (err){
        console.error('Error sending message:', err.stack);
        res.status(500).json({ success: false, message: 'Failed to send message'});
    }
});

pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    console.log('Connected to PostgreSQL database')
    release();
});

app.get('/', (req, res) => {
    res.send('Back is running');
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
