require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const WebSocket = require('ws');
const http = require('http');
const app = express();
const port = process.env.PORT || 3001;

const server = http.createServer(app);

const wss = new WebSocket.Server({ server });

const jwtSecret = process.env.JWT_SECRET || 'testingsecretkey';


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


const connectedClients = new Set();

wss.on('connection', ws => {
    console.log('Client connected via WebSocket');

    connectedClients.add(ws);

    ws.on('message', message => {
        console.log(`Received message from client: ${message}`);
    });

    ws.on('close', () => {
        console.log('Client disconnected from WebSocket');
        connectedClients.delete(ws);
    });


    ws.on('error', error => {
        console.log(`WebSocket error: ${error}`);
        connectedClients.delete(ws);
    });



})


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
        const chatId = parseInt(req.query.chat_id);
        const limit = parseInt(req.query.limit) || 50;
        const beforeId = req.query.before_id ? parseInt(req.query.before_id) : null;

        if (isNaN(chatId)) {
            return res.status(400).json({ success: false, message: 'chat_id parameter is required and must be a number.' });
        }

        if (limit < 0 || limit > 100) {
            return (res.status(400)).json({
                success: false,
                message: "Invalid limit parameter"
            });
        }

        const userId = req.user.userId;

        try {
            if (chatId !== 1) {
                const isParticipant = await pool.query(
                    'SELECT 1 FROM user_chats WHERE user_id = $1 AND chat_id = $2',
                    [userId, chatId]
                );

                if (isParticipant.rows.length === 0) {
                    return res.status(403).json({
                        success: false,
                        message: 'Forbidden: You are not a member of this chat.'
                    });
                };
            }
            let query = `
                SELECT
                    m.id,
                    m.text,
                    m.sender_id,
                    u.login as sender_login,
                    m.created_at
                FROM 
                    messages m
                JOIN
                    users u ON m.sender_id = u.id
                WHERE
                    m.chat_id = $1
                `;

            const queryParams = [chatId];

            if (beforeId !== null) {
                query += ` AND m.id < $${queryParams.length + 1}`;
                queryParams.push(beforeId);
            }

            query += ` ORDER BY m.created_at DESC, m.id DESC`;
            query += ` LIMIT $${queryParams.length + 1}`;
            queryParams.push(limit + 1)

            console.log(`Executing messages query for chat ${chatId}: ${query, queryParams}`);

            const result = await pool.query(query, queryParams);
            const messages = result.rows;

            const hasMore = messages.length > limit;

            const messagesToSend = messages.slice(0, limit);

            res.status(200).json({
                success: true,
                messages: messagesToSend,
                hasMore: hasMore
            });

        } catch (err) {
            console.error('Error fetching messages:', err.stack);
            res.status(500).json({
                success: false,
                message: 'Failed to fetch messages'
            });

        }
    });

app.post('/api/messages', authenticateToken, async (req, res) => {
    const senderId = req.user.userId;
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
        return res.status(400).json({ success: false, message: 'message text can not be empty' });
    }
    const chatId = 1;

    try {
        const result = await pool.query(
            'INSERT INTO messages (chat_id, sender_id, text) VALUES ($1,$2,$3) RETURNING id, chat_id, sender_id, text, created_at',
            [chatId, senderId, text]
        );
        const newMessage = result.rows[0];

        const senderResult = await pool.query('SELECT login FROM users WHERE id = $1', [senderId]);
        const senderLogin = senderResult.rows[0].login;

        const messageDataToBroadcast = {
            id: newMessage.id,
            chat_id: newMessage.chat_id,
            sender_id: newMessage.sender_id,
            text: newMessage.text,
            created_at: newMessage.created_at,
            sender_login: senderLogin
        }

        const new_message_notification = {
            type: 'new_message',
            messageData: messageDataToBroadcast
        };

        connectedClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(new_message_notification));
            }
        })

        res.status(201).json({
            success: true,
            message: 'Message sent successfully',
            messageData: messageDataToBroadcast
        })

    } catch (err) {
        console.error('Error sending message:', err.stack);
        res.status(500).json({ success: false, message: 'Failed to send message' });
    }
});


app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    const messageId = req.params.id;
    const userId = req.user.userId;


    try {
        const messageResult = await pool.query(
            'SELECT sender_id FROM messages WHERE id = $1',
            [messageId]
        );

        if (messageResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Message not found'
            })
        }

        const message = messageResult.rows[0];

        if (message.sender_id !== userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only delete your own messages'
            })
        }

        await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);

        const deleteNotification = {
            type: 'message_deleted',
            messageId: messageId
        };

        connectedClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(deleteNotification));
            }
        });

        res.status(200).json({
            success: true,
            message: 'Message deleted successfully',
            id: messageId
        })

    } catch (err) {
        console.error('Error deleting message:', err.stack);
        res.status(500).json({
            success: false,
            message: 'Failed to delete message'
        })
    }
})

app.put('/api/messages/:id', authenticateToken, async (req, res) => {
    const messageId = req.params.id;
    const userId = req.user.userId;
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
        return res.status(400).json({
            success: false,
            message: 'New message text can not be empty'
        })
    }

    try {
        const messageResult = await pool.query(
            'SELECT sender_id FROM messages WHERE id = $1',
            [messageId]
        );

        if (messageResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                success: false,
                message: 'Message not found'
            })

        }

        const message = messageResult.rows[0];

        if (message.sender_id !== userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only your messages'
            })
        }

        const updateResult = await pool.query(
            'UPDATE messages SET text = $1 WHERE id = $2 RETURNING id, chat_id, sender_id, text, created_at', [text, messageId]
        );

        const updatedMessageData = updateResult.rows[0];

        const senderLogin = req.user.login;

        updatedMessageData.sender_login = senderLogin;

        res.status(200).json({
            success: true,
            message: 'Message updated successfully',
            updatedMessageData: updatedMessageData
        });
        const updateNotification = {
            type: 'message_updated',
            messageData: updatedMessageData
        }
        connectedClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(updateNotification));
            }
        });
        console.log('WebSocket notification sent:', updateNotification);

    } catch (err) {
        console.error('Error editing message:', err.stack);
        res.status(500).json({
            success: false,
            message: 'Failed to edit message'
        });
    }
})


app.get(
    '/api/chats', 
    authenticateToken,
    async (req, res) => {
        const userId = req.user.userId;

        try {
            const query = `
            SELECT 
                c.id AS chat_id,
                c.type AS chat_type,
                c.created_at AS chat_created_at,
                (SELECT u2.login FROM user_chats uc2 JOIN users u2 ON uc2.user_id = u2.id WHERE uc2.chat_id = c.id AND uc2.user_id != $1 LIMIT 1) AS other_participant_login
            FROM 
                user_chats uc
            JOIN
                chats c ON uc.chat_id = c.id
            WHERE
                uc.user_id = $1
            ORDER BY 
                c.created_at DESC;
            `;

            const result = await pool.query(query, [userId]);
            const chats = result.rows;

            const formattedChats = chats.map(chat =>{
                let chatName = `Chat ${chat.chat_id}`;

                if (chat.chat_type === 'personal' && chat.other_participant_login){
                    chatName = chat.other_participant_login;
                }else if (chat.chat_id === 1 && chat.other_participant_login){
                    chatName = 'Public Chat';
                }

                return {
                    id: chat.chat_id,
                    type: chat.chat_type,
                    name: chatName,
                    createdAt: chat.chat_created_at
                }
            }) 
            res.status(200).json({
                success: true,
                chats: formattedChats
            })
        } catch (err) {
            console.error('Error fetching user chats:', err.stack);
            res.status(500).json({
                success: false,
                message: 'Failed to fetch user chats'
            })
        }
    }
)



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

server.listen(port, () => {
    console.log(`HTTP and WebSocket server running on port ${port}`);
});