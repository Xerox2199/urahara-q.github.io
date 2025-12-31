require('dotenv').config();
const express = require('express');
const session = require('cookie-session');
const axios = require('axios');
const multer = require('multer');
const FormData = require('form-data');
const fs = require('fs');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const CONFIG = {
    guildId: '1455708867798372354',
    roleId: '1455711356765339802',
    adminId: '1384238328223764591',
    ideasFile: 'ideas.json'
};

if (!fs.existsSync(CONFIG.ideasFile)) fs.writeFileSync(CONFIG.ideasFile, JSON.stringify([]));

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ name: 'session', keys: [process.env.SESSION_SECRET || 'aot_secret'], maxAge: 24 * 60 * 60 * 1000 }));

app.get('/', (req, res) => {
    if (!req.session.user) {
        const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=code&scope=identify`;
        return res.redirect(authUrl);
    }
    res.render('index', { user: req.session.user, adminId: CONFIG.adminId });
});

app.get('/callback', async (req, res) => {
    const code = req.query.code;
    try {
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.CLIENT_ID, client_secret: process.env.CLIENT_SECRET,
            code, grant_type: 'authorization_code', redirect_uri: process.env.REDIRECT_URI, scope: 'identify',
        }).toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
        });
        req.session.user = userRes.data;
        res.redirect('/');
    } catch (err) { res.send("Erreur Discord"); }
});

app.post('/submit-review', upload.single('imageFile'), async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "Auth required" });
    try {
        const discordRes = await axios.get(`https://discord.com/api/v10/guilds/${CONFIG.guildId}/members/${req.session.user.id}`, {
            headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
        });
        if (!discordRes.data.roles.includes(CONFIG.roleId)) return res.status(403).json({ error: "No permission" });
        const { message, stars } = req.body;
        const form = new FormData();
        form.append('payload_json', JSON.stringify({
            embeds: [{ title: "New Review", description: message, color: 16777215, fields: [{ name: "Rating", value: "⭐".repeat(stars) }], footer: { text: `By ${req.session.user.username}` } }]
        }));
        if (req.file) form.append('file', req.file.buffer, req.file.originalname);
        await axios.post(process.env.WEBHOOK_URL, form, { headers: form.getHeaders() });
        res.json({ success: true });
    } catch (err) { res.status(403).json({ error: "API Error" }); }
});

app.post('/submit-idea', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "Auth required" });
    const ideas = JSON.parse(fs.readFileSync(CONFIG.ideasFile));
    ideas.push({ id: Date.now(), user: req.session.user.username, avatar: `https://cdn.discordapp.com/avatars/${req.session.user.id}/${req.session.user.avatar}.png`, message: req.body.ideaMessage });
    fs.writeFileSync(CONFIG.ideasFile, JSON.stringify(ideas, null, 2));
    res.json({ success: true });
});

app.post('/delete-idea', (req, res) => {
    if (!req.session.user || req.session.user.id !== CONFIG.adminId) return res.status(403).send("Denied");
    
    let ideas = [];
    try {
        ideas = JSON.parse(fs.readFileSync(CONFIG.ideasFile));
    } catch (e) { ideas = []; }

    const ideaIdToDelete = req.body.id;

    // On vérifie que i.id existe avant de faire le toString()
    ideas = ideas.filter(i => i && i.id && i.id.toString() !== ideaIdToDelete.toString());
    
    fs.writeFileSync(CONFIG.ideasFile, JSON.stringify(ideas, null, 2));
    res.redirect('/admin');
});

app.get('/logout', (req, res) => { req.session = null; res.redirect('/'); });
app.get('/faq', (req, res) => { res.render('faq'); });
app.get('/admin', (req, res) => {
    if (!req.session.user || req.session.user.id !== CONFIG.adminId) return res.redirect('/');
    const ideas = JSON.parse(fs.readFileSync(CONFIG.ideasFile));
    res.render('admin', { ideas });
});

app.listen(3000, () => console.log('Serveur lancé sur http://localhost:3000'));