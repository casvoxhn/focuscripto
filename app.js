// app.js - TODO EN UN SOLO ARCHIVO PARA RAILWAY
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Configuración de la base de datos (Railway proporciona DATABASE_URL automáticamente)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Variables de entorno que necesitas configurar en Railway
const JWT_SECRET = process.env.JWT_SECRET || 'cambia-esto-por-algo-seguro';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;

// HTML de la página principal (todo en uno)
const HTML_PAGE = `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FocusCripto - Convierte audios de Telegram en blogs</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-50">
    <div id="app" class="min-h-screen">
        <!-- Header -->
        <header class="bg-white shadow-sm fixed w-full top-0 z-50">
            <nav class="container mx-auto px-4 py-4 flex justify-between items-center">
                <h1 class="text-2xl font-bold text-purple-600">
                    <i class="fas fa-robot mr-2"></i>FocusCripto
                </h1>
                <div class="space-x-4">
                    <button onclick="showLogin()" class="text-gray-600 hover:text-purple-600">Iniciar sesión</button>
                    <button onclick="showRegister()" class="bg-purple-600 text-white px-4 py-2 rounded hover:bg-purple-700">Empezar</button>
                </div>
            </nav>
        </header>

        <!-- Contenido Principal -->
        <main class="pt-20">
            <!-- Página de inicio -->
            <div id="home" class="container mx-auto px-4 py-12 text-center">
                <h2 class="text-4xl font-bold mb-6">Convierte tus audios de Telegram en blogs virales</h2>
                <p class="text-xl text-gray-600 mb-8">Automatiza tu contenido con IA. Solo $9.99/mes</p>
                <button onclick="showRegister()" class="bg-purple-600 text-white px-8 py-4 rounded-lg text-lg hover:bg-purple-700">
                    Prueba gratis 7 días
                </button>
                
                <div class="grid md:grid-cols-3 gap-8 mt-16">
                    <div class="bg-white p-6 rounded-lg shadow">
                        <i class="fas fa-microphone text-4xl text-purple-600 mb-4"></i>
                        <h3 class="text-xl font-semibold mb-2">Envía audios</h3>
                        <p class="text-gray-600">Graba en Telegram y envía</p>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow">
                        <i class="fas fa-magic text-4xl text-purple-600 mb-4"></i>
                        <h3 class="text-xl font-semibold mb-2">IA procesa</h3>
                        <p class="text-gray-600">GPT-4 optimiza tu contenido</p>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow">
                        <i class="fab fa-wordpress text-4xl text-purple-600 mb-4"></i>
                        <h3 class="text-xl font-semibold mb-2">Publica automático</h3>
                        <p class="text-gray-600">Directo a tu WordPress</p>
                    </div>
                </div>
            </div>

            <!-- Formulario de Login -->
            <div id="login" class="container mx-auto px-4 py-12 max-w-md" style="display:none;">
                <div class="bg-white p-8 rounded-lg shadow">
                    <h2 class="text-2xl font-bold mb-6">Iniciar sesión</h2>
                    <form onsubmit="handleLogin(event)">
                        <input type="email" id="loginEmail" placeholder="Email" required 
                               class="w-full p-3 border rounded mb-4">
                        <input type="password" id="loginPassword" placeholder="Contraseña" required 
                               class="w-full p-3 border rounded mb-4">
                        <button type="submit" class="w-full bg-purple-600 text-white p-3 rounded hover:bg-purple-700">
                            Entrar
                        </button>
                    </form>
                    <p class="mt-4 text-center">
                        ¿No tienes cuenta? <a href="#" onclick="showRegister()" class="text-purple-600">Regístrate</a>
                    </p>
                </div>
            </div>

            <!-- Formulario de Registro -->
            <div id="register" class="container mx-auto px-4 py-12 max-w-md" style="display:none;">
                <div class="bg-white p-8 rounded-lg shadow">
                    <h2 class="text-2xl font-bold mb-6">Crear cuenta</h2>
                    <form onsubmit="handleRegister(event)">
                        <input type="text" id="registerName" placeholder="Nombre" required 
                               class="w-full p-3 border rounded mb-4">
                        <input type="email" id="registerEmail" placeholder="Email" required 
                               class="w-full p-3 border rounded mb-4">
                        <input type="password" id="registerPassword" placeholder="Contraseña" required 
                               class="w-full p-3 border rounded mb-4">
                        <button type="submit" class="w-full bg-purple-600 text-white p-3 rounded hover:bg-purple-700">
                            Crear cuenta
                        </button>
                    </form>
                    <p class="mt-4 text-center">
                        ¿Ya tienes cuenta? <a href="#" onclick="showLogin()" class="text-purple-600">Inicia sesión</a>
                    </p>
                </div>
            </div>

            <!-- Dashboard -->
            <div id="dashboard" class="container mx-auto px-4 py-12" style="display:none;">
                <div class="bg-white p-8 rounded-lg shadow">
                    <h2 class="text-2xl font-bold mb-6">Panel de Control</h2>
                    
                    <div class="grid md:grid-cols-2 gap-6 mb-8">
                        <!-- Configuración Telegram -->
                        <div>
                            <h3 class="text-lg font-semibold mb-4">Telegram Bot</h3>
                            <input type="text" id="telegramToken" placeholder="Token del bot (de @BotFather)" 
                                   class="w-full p-3 border rounded mb-2">
                            <p class="text-sm text-gray-600">Ejemplo: 123456789:ABCdefGHIjklmNOPqrstUVwxyz</p>
                        </div>
                        
                        <!-- Configuración WordPress -->
                        <div>
                            <h3 class="text-lg font-semibold mb-4">WordPress</h3>
                            <input type="url" id="wpUrl" placeholder="URL de tu sitio" 
                                   class="w-full p-3 border rounded mb-2">
                            <input type="text" id="wpToken" placeholder="Token de aplicación" 
                                   class="w-full p-3 border rounded mb-2">
                            <p class="text-sm text-gray-600">Ve a WordPress > Usuarios > Tu perfil > Application Passwords</p>
                        </div>
                    </div>
                    
                    <button onclick="saveConfig()" class="bg-purple-600 text-white px-6 py-3 rounded hover:bg-purple-700">
                        Guardar configuración
                    </button>
                    
                    <div class="mt-8 p-4 bg-gray-100 rounded">
                        <h3 class="font-semibold mb-2">Instrucciones:</h3>
                        <ol class="list-decimal list-inside space-y-2 text-sm">
                            <li>Crea un bot en Telegram con @BotFather</li>
                            <li>Copia el token y pégalo arriba</li>
                            <li>Genera un token en WordPress</li>
                            <li>Guarda la configuración</li>
                            <li>¡Empieza a enviar audios a tu bot!</li>
                        </ol>
                    </div>
                    
                    <div class="mt-4">
                        <button onclick="logout()" class="text-red-600 hover:underline">Cerrar sesión</button>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        // Variables globales
        let token = localStorage.getItem('token');
        let currentUser = null;

        // Funciones de navegación
        function showHome() {
            document.getElementById('home').style.display = 'block';
            document.getElementById('login').style.display = 'none';
            document.getElementById('register').style.display = 'none';
            document.getElementById('dashboard').style.display = 'none';
        }

        function showLogin() {
            document.getElementById('home').style.display = 'none';
            document.getElementById('login').style.display = 'block';
            document.getElementById('register').style.display = 'none';
            document.getElementById('dashboard').style.display = 'none';
        }

        function showRegister() {
            document.getElementById('home').style.display = 'none';
            document.getElementById('login').style.display = 'none';
            document.getElementById('register').style.display = 'block';
            document.getElementById('dashboard').style.display = 'none';
        }

        function showDashboard() {
            document.getElementById('home').style.display = 'none';
            document.getElementById('login').style.display = 'none';
            document.getElementById('register').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            loadConfig();
        }

        // Manejo de autenticación
        async function handleLogin(e) {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password})
                });

                const data = await response.json();
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    token = data.token;
                    currentUser = data.user;
                    showDashboard();
                    alert('¡Bienvenido!');
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (err) {
                alert('Error al conectar');
            }
        }

        async function handleRegister(e) {
            e.preventDefault();
            const name = document.getElementById('registerName').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name, email, password})
                });

                const data = await response.json();
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    token = data.token;
                    currentUser = data.user;
                    showDashboard();
                    alert('¡Cuenta creada! Tienes 7 días gratis');
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (err) {
                alert('Error al conectar');
            }
        }

        async function saveConfig() {
            const config = {
                telegramToken: document.getElementById('telegramToken').value,
                wpUrl: document.getElementById('wpUrl').value,
                wpToken: document.getElementById('wpToken').value
            };

            if (!config.telegramToken || !config.wpUrl || !config.wpToken) {
                alert('Por favor completa todos los campos');
                return;
            }

            try {
                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify(config)
                });

                if (response.ok) {
                    alert('¡Configuración guardada! Ya puedes usar tu bot');
                } else {
                    alert('Error al guardar');
                }
            } catch (err) {
                alert('Error al conectar');
            }
        }

        async function loadConfig() {
            try {
                const response = await fetch('/api/config', {
                    headers: {'Authorization': 'Bearer ' + token}
                });

                if (response.ok) {
                    const config = await response.json();
                    if (config.telegram_token) {
                        document.getElementById('telegramToken').value = config.telegram_token;
                        document.getElementById('wpUrl').value = config.wordpress_url || '';
                        document.getElementById('wpToken').value = config.wordpress_token || '';
                    }
                }
            } catch (err) {
                console.error('Error al cargar config');
            }
        }

        function logout() {
            localStorage.removeItem('token');
            token = null;
            currentUser = null;
            showHome();
        }

        // Verificar si hay sesión activa
        if (token) {
            showDashboard();
        }
    </script>
</body>
</html>
`;

// Servir la página principal
app.get('/', (req, res) => {
    res.send(HTML_PAGE);
});

// Inicializar base de datos
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255),
                email VARCHAR(255) UNIQUE,
                password_hash VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS configurations (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                telegram_token VARCHAR(255),
                wordpress_url VARCHAR(255),
                wordpress_token VARCHAR(255),
                webhook_url VARCHAR(255)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                chat_id BIGINT,
                content TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('Base de datos inicializada');
    } catch (err) {
        console.error('Error al inicializar DB:', err);
    }
}

// API: Registro
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
            [name, email, hashedPassword]
        );
        
        const token = jwt.sign({ id: result.rows[0].id }, JWT_SECRET);
        
        res.json({ token, user: result.rows[0] });
    } catch (err) {
    console.error('Error en registro:', err);
    res.status(400).json({ error: 'Error al crear cuenta. Intenta de nuevo.' });
}
});

// API: Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Usuario no encontrado' });
        }
        
        const validPassword = await bcrypt.compare(password, result.rows[0].password_hash);
        
        if (!validPassword) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }
        
        const token = jwt.sign({ id: result.rows[0].id }, JWT_SECRET);
        
        res.json({ 
            token, 
            user: {
                id: result.rows[0].id,
                name: result.rows[0].name,
                email: result.rows[0].email
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// API: Guardar configuración
app.post('/api/config', authenticateToken, async (req, res) => {
    const { telegramToken, wpUrl, wpToken } = req.body;
    const userId = req.user.id;
    
    try {
        // Generar URL del webhook
        const webhookUrl = `https://${req.get('host')}/webhook/${userId}`;
        
        // Guardar o actualizar configuración
        await pool.query(`
            INSERT INTO configurations (user_id, telegram_token, wordpress_url, wordpress_token, webhook_url)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id) DO UPDATE
            SET telegram_token = $2, wordpress_url = $3, wordpress_token = $4, webhook_url = $5
        `, [userId, telegramToken, wpUrl, wpToken, webhookUrl]);
        
        // Configurar webhook en Telegram
        if (telegramToken) {
            await axios.post(`https://api.telegram.org/bot${telegramToken}/setWebhook`, {
                url: webhookUrl
            });
        }
        
        res.json({ success: true, webhookUrl });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al guardar' });
    }
});

// API: Obtener configuración
app.get('/api/config', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM configurations WHERE user_id = $1',
            [req.user.id]
        );
        
        res.json(result.rows[0] || {});
    } catch (err) {
        res.status(500).json({ error: 'Error al cargar' });
    }
});

// Webhook de Telegram
app.post('/webhook/:userId', async (req, res) => {
    const { userId } = req.params;
    const { message } = req.body;
    
    if (!message) return res.json({ ok: true });
    
    try {
        // Obtener configuración del usuario
        const configResult = await pool.query(
            'SELECT * FROM configurations WHERE user_id = $1',
            [userId]
        );
        
        if (!configResult.rows[0]) {
            return res.json({ ok: true });
        }
        
        const config = configResult.rows[0];
        
        // Procesar comando
        if (message.text === 'Publicar') {
            await publishContent(userId, config, message.chat.id);
        } else if (message.text === 'Reiniciar') {
            await pool.query('DELETE FROM messages WHERE user_id = $1 AND chat_id = $2', [userId, message.chat.id]);
            await sendTelegramMessage(config.telegram_token, message.chat.id, '✅ Contenido eliminado. Puedes empezar de nuevo.');
        } else {
            // Guardar mensaje
            let content = message.text || '';
            
            // Si es audio, transcribir
            if (message.voice) {
                content = await transcribeAudio(config.telegram_token, message.voice.file_id);
            }
            
            await pool.query(
                'INSERT INTO messages (user_id, chat_id, content) VALUES ($1, $2, $3)',
                [userId, message.chat.id, content]
            );
            
            await sendTelegramMessage(config.telegram_token, message.chat.id, '✍️ Recibido...');
        }
        
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.json({ ok: true });
    }
});

// Funciones auxiliares
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

async function transcribeAudio(botToken, fileId) {
    try {
        // Obtener archivo de Telegram
        const fileInfo = await axios.get(`https://api.telegram.org/bot${botToken}/getFile?file_id=${fileId}`);
        const filePath = fileInfo.data.result.file_path;
        const fileUrl = `https://api.telegram.org/file/bot${botToken}/${filePath}`;
        
        // Aquí normalmente se transcribiría con OpenAI Whisper
        // Por simplicidad, retornamos un texto de ejemplo
        return "Audio recibido y procesado";
    } catch (err) {
        console.error('Error transcribiendo:', err);
        return "Error al procesar audio";
    }
}

async function publishContent(userId, config, chatId) {
    try {
        // Obtener todos los mensajes
        const messages = await pool.query(
            'SELECT * FROM messages WHERE user_id = $1 AND chat_id = $2 ORDER BY timestamp',
            [userId, chatId]
        );
        
        if (messages.rows.length === 0) {
            await sendTelegramMessage(config.telegram_token, chatId, '❌ No hay contenido para publicar');
            return;
        }
        
        // Combinar contenido
        const content = messages.rows.map(m => m.content).join('\n\n');
        
        // Generar artículo con IA (simplificado)
        const article = {
            title: "🚀 Nuevo artículo de crypto",
            content: `<p>${content}</p>`
        };
        
        // Publicar en WordPress
        const wpAuth = Buffer.from(`:${config.wordpress_token}`).toString('base64');
        
        await axios.post(
            `${config.wordpress_url}/wp-json/wp/v2/posts`,
            {
                title: article.title,
                content: article.content,
                status: 'draft'
            },
            {
                headers: {
                    'Authorization': `Basic ${wpAuth}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        // Limpiar mensajes
        await pool.query('DELETE FROM messages WHERE user_id = $1 AND chat_id = $2', [userId, chatId]);
        
        await sendTelegramMessage(config.telegram_token, chatId, '✅ Artículo publicado en WordPress!');
    } catch (err) {
        console.error('Error publicando:', err);
        await sendTelegramMessage(config.telegram_token, chatId, '❌ Error al publicar');
    }
}

async function sendTelegramMessage(token, chatId, text) {
    try {
        await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
            chat_id: chatId,
            text: text
        });
    } catch (err) {
        console.error('Error enviando mensaje:', err);
    }
}

// Iniciar servidor
app.listen(PORT, async () => {
    await initDB();
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
