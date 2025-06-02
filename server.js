require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const WebSocket = require('ws');
const http = require('http');
const { type } = require('os');
const { send } = require('process');
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

const authenticatedClients = new Set();


wss.on('connection', ws => {
    console.log('Client connected via WebSocket');

    const handleAuthMessage = message => {
        let authData;
        console.log('Client auth via WebSocket');

        try {
            authData = JSON.parse(message);
        } catch (err) {
            console.error('Failed to parse WebSocket auth message', err);
            ws.send(JSON.stringify({
                type: 'error',
                message: 'Invalid JSON format'
            }));
            ws.close(1008, 'Invalid message');
            return
        }

        if (authData.type === 'auth' && authData.token) {
            jwt.verify(authData.token, jwtSecret, (err, decoded) => {
                if (err) {
                    ws.send(JSON.stringify({
                        type: 'auth_failed',
                        message: 'Invalid token'
                    }));
                    ws.close(1008, 'Authentication failed');
                } else {
                    console.log('WebSocket client authenticated. User ID:', decoded.userId);

                    ws.userId = decoded.userId;
                    ws.login = decoded.login;

                    authenticatedClients.add(ws);
                    console.log(`User ${ws.userId} authenticated via WS. Total authenticated clients${Array.from(authenticatedClients)}`);

                    ws.send(JSON.stringify({
                        type: 'auth_success',
                        message: 'Authentication successful'
                    }));

                    ws.off('message', handleAuthMessage);
                    ws.on('message', handleClientMessage);
                }
            })

        } else {
            console.warn('WebSocket client sent non-auth first message or invalid auth format.');
            ws.send(JSON.stringify({ type: 'error', message: 'Authentication required as the first message' }));
            ws.close(1008, 'Authentication required');
        }
    };

    ws.once('message', handleAuthMessage);

    const handleClientMessage = message => {
        if (!ws.userId) {
            console.warn('Received message from unauthenticated client on handleClientMessage');
            ws.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
            ws.close(1008, 'Authentication required');
            return;
        }

        console.log(`Received message from authenticated client (User ${ws.userId}):`, message);
    };

    ws.on('close', (code, reason) => {
        console.log(`Client disconnected. Code: ${code}, Reason: ${reason ? reason.toString() : 'N/A'}`);
        if (ws.userId) {
            authenticatedClients.delete(ws);
            console.log(`Authenticated client (User ${ws.userId}) removed. Total authenticated clients: ${authenticatedClients.size}`);
        } else {
            console.log(`Unauthenticated client disconnected. Total authenticated clients: ${authenticatedClients.size}`);
        }

    });

    ws.on('error', error => {
        console.log(`WebSocket error: ${error.message}`);
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

            console.log(`Executing messages query for chat ${chatId}: ${query}, ${queryParams}`);

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
    const { text, chatId } = req.body;

    if (!text || text.trim().length === 0) {
        return res.status(400).json({ success: false, message: 'message text can not be empty' });
    }

    if (isNaN(chatId)) {
        return res.status(400).json({ success: false, message: 'chat_id parameter is required and must be a number.' });
    }

    try {
        if (chatId !== 1) {
            const isParticipant = await pool.query(
                'SELECT 1 FROM user_chats WHERE user_id = $1 AND chat_id = $2',
                [senderId, chatId]
            );

            if (isParticipant.rows.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Forbidden: You are not a member of this chat.'
                });
            };
        }

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

        const participantsResult = await pool.query(
            'SELECT user_id FROM user_chats WHERE chat_id = $1',
            [chatId]
        );

        const participantUserIds = new Set(participantsResult.rows.map(row => row.user_id));

        console.log(`Broadcasting message for chat ${chatId} to participants:`, Array.from(participantUserIds));
        console.log(Array.from(authenticatedClients));
        authenticatedClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && participantUserIds.has(client.userId)) {
                client.send(JSON.stringify(new_message_notification));
                console.log(`Sent message notification to user ${client.userId} for chat: ${chatId}`);
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
            'SELECT sender_id, chat_id FROM messages WHERE id = $1',
            [messageId]
        );

        if (messageResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Message not found'
            });
        }

        const message = messageResult.rows[0];
        const messageChatId = message.chat_id;

        if (String(message.sender_id) !== String(userId)) {
            return res.status(403).json({
                success: false,
                message: 'You can only delete your own messages'
            });
        }

        await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);

        const participantsResult = await pool.query(
            'SELECT user_id FROM user_chats WHERE chat_id = $1',
            [messageChatId]
        );
        const participantUserIds = new Set(participantsResult.rows.map(row => row.user_id));

        const deleteNotification = {
            type: 'message_deleted',
            messageId: messageId,
            chatId: messageChatId
        };

        authenticatedClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && participantUserIds.has(client.userId)) {
                client.send(JSON.stringify(deleteNotification));
                console.log(`Sent delete notification for message ${messageId} to user ${client.userId} for chat ${messageChatId}`);
            }
        });

        res.status(200).json({
            success: true,
            message: 'Message deleted successfully',
            messageId: messageId,
            chatId: messageChatId
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
            'SELECT sender_id, chat_id FROM messages WHERE id = $1',
            [messageId]
        );

        if (messageResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Message not found'
            });
        }

        const message = messageResult.rows[0];
        const messageChatId = message.chat_id;

        if (message.sender_id !== userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only edit your messages'
            });
        }

        const updateResult = await pool.query(
            'UPDATE messages SET text = $1 WHERE id = $2 RETURNING id, chat_id, sender_id, text, created_at',
            [text, messageId]
        );

        const updatedMessageData = updateResult.rows[0];

        const senderLoginResult = await pool.query(
            'SELECT login FROM users WHERE id = $1',
            [updatedMessageData.sender_id]
        );
        updatedMessageData.sender_login = senderLoginResult.rows[0].login;

        const participantsResult = await pool.query(
            'SELECT user_id FROM user_chats WHERE chat_id = $1',
            [messageChatId]
        );
        const participantUserIds = new Set(participantsResult.rows.map(row => row.user_id));

        const updateNotification = {
            type: 'message_updated',
            messageData: updatedMessageData

        }
        authenticatedClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && participantUserIds.has(client.userId)) {
                client.send(JSON.stringify(updateNotification));
                console.log(`Sent update notification for message ${updatedMessageData.id} to user ${client.userId} for chat ${messageChatId}`);
            }
        });

        console.log('WebSocket notification sent:', updateNotification);

        res.status(200).json({
            success: true,
            message: 'Message updated successfully',
            updatedMessageData: updatedMessageData
        });

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
        const currentUserId = req.user.userId;

        try {
            const chatsWithParticipantsAndLastMessageResult = await pool.query(
                `SELECT
                c.id,
                c.type,
                c.created_at,
                lm.text AS last_message_text,
                lm.created_at AS last_message_created_at,
                
                CASE
                    WHEN c.type = 'personal' THEN (
                    SELECT jsonb_build_object('id', u.id, 'login', u.login)
                    FROM user_chats uc2
                    JOIN users u ON uc2.user_id = u.id
                    WHERE uc2.chat_id = c.id AND uc2.user_id != $1
                    LIMIT 1
                    )
                    ELSE NULL
                END AS other_participant
                FROM chats c
                JOIN user_chats uc1 ON c.id = uc1.chat_id 
                LEFT JOIN (
                SELECT
                    m.chat_id,
                    m.text,
                    m.created_at,
                    ROW_NUMBER() OVER(PARTITION BY m.chat_id ORDER BY m.created_at DESC) as rn
                FROM messages m
                ) lm ON c.id = lm.chat_id AND lm.rn = 1
                WHERE uc1.user_id = $1
                GROUP BY c.id, c.type, c.created_at, lm.text, lm.created_at 
                ORDER BY lm.created_at DESC NULLS LAST; 
            `,
                [currentUserId]
            );


            const formattedChats = chatsWithParticipantsAndLastMessageResult.rows.map(row => {
                const chatName = row.type === 'personal' && row.other_participant
                    ? row.other_participant.login
                    : `Chat ${row.id}`;

                return {
                    id: row.id,
                    name: chatName,
                    type: row.type,
                    createdAt: row.created_at,
                    lastMessageText: row.last_message_text,
                    lastMessageCreatedAt: row.last_message_created_at
                };
            });


            res.status(200).json({
                success: true,
                chats: formattedChats
            });

        } catch (err) {
            console.error('Error fetching chats:', err.stack);
            res.status(500).json({
                success: false,
                message: 'Failed to fetch chats.'
            });
        }
    }
)


app.post('/api/chats', authenticateToken, async (req, res) => {
    const chatType = 'personal';
    const otherUserLogin = req.body.otherUserLogin.trim();
    const currentUserId = req.user.userId;
    const currentUserLogin = req.user.login.trim();

    if (!otherUserLogin || typeof otherUserLogin !== 'string' || otherUserLogin.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'otherUserLogin is required'
        });
    }

    if (otherUserLogin === currentUserLogin) {
        return res.status(400).json({
            success: false,
            message: 'Cannot create a personal chat with yourself'
        });
    }

    try {

        const otherUserResult = await pool.query(
            'SELECT id FROM users WHERE login = $1',
            [otherUserLogin]
        );

        if (otherUserResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: `User with login ${otherUserLogin} not found.`
            });
        }

        const otherUserId = otherUserResult.rows[0].id;

        const existingChatResult = await pool.query(
            `SELECT c.id, c.type, c.created_at  
            FROM user_chats uc1
            JOIN user_chats uc2 ON uc1.chat_id = uc2.chat_id
            JOIN chats c ON uc1.chat_id = c.id
            WHERE uc1.user_id = $1 AND uc2.user_id = $2 AND c.type = $3`,
            [currentUserId, otherUserId, chatType]
        );

        if (existingChatResult.rows.length > 0) {
            const existingChatId = existingChatResult.rows[0].chat_id;
            console.log(`Personal chat already exists between ${currentUserLogin} and ${otherUserLogin}`);

            return res.status(200).json({
                success: true,
                message: 'Personal chat already exists.',
                chat: {
                    id: existingChatId,
                    type: chatType,
                    name: otherUserLogin
                }
            });
        }

        console.log(`Creating new personal chat between ${currentUserLogin} and ${otherUserLogin}`);

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const newChatResult = await client.query(
                'INSERT INTO chats (type) VALUES ($1) RETURNING id, type, created_at',
                [chatType]
            );

            const newChat = newChatResult.rows[0];
            const newChatId = newChat.id;

            await client.query(
                'INSERT INTO user_chats (chat_id, user_id) VALUES ($1, $2), ($1, $3)',
                [newChatId, currentUserId, otherUserId]
            );

            await client.query('COMMIT');

            console.log(`New personal chat created with ID: ${newChatId}`);

            const newChatNotification = {
                type: 'new_chat',
                chat: {
                    id: newChatId,
                    type: newChat.type,
                    createdAt: newChat.created_at,
                    participants: [
                        { id: currentUserId, login: currentUserLogin },
                        { id: otherUserId, login: otherUserLogin }
                    ]
                }
            };

            Array.from(authenticatedClients)
                .filter(client => String(client.userId) === String(currentUserId) || String(client.userId) === String(otherUserId))
                .forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(newChatNotification))
                    }
                })


            const chatName = otherUserLogin;
            res.status(201).json({
                success: true,
                message: 'Personal chat created successfully.',
                chat: {
                    id: newChatId,
                    type: newChat.type,
                    name: chatName,
                    createdAt: newChat.created_at
                }
            })
        } catch (transactionErr) {
            await client.query('ROLLBACK');
            throw transactionErr;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('Error creating chat:', err.stack);
        if (!res.headersSent) {
            res.status(500).json({
                success: false,
                message: 'Failed to create chat.'
            });
        }
    }

})




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