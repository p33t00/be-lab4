const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
require('dotenv').config();

const db = require('./database.js');

app.set('view-engine', 'ejs');

app.use(cors({ origin: '*' }));
app.use(express.urlencoded({extended: false}));
app.use(express.json());

var currentKey = ''
var currentPassword = ''
var userSession;

app.get('/', authMiddleware(), (req, res) => {
	res.redirect('/start')
});

app.get('/start', authMiddleware(), (req, res) => {
	res.render('pages/start.ejs', {username: req.username})
});

app.get('/admin', authMiddleware(['admin']), async (req, res) => {
	const users = await db.getAllUsers();
	res.render('pages/admin.ejs', {users: users})
});

app.get('/teacher', authMiddleware(['admin', 'teacher']), async (req, res) => {
	res.render('pages/teacher.ejs')
});

app.get('/student/:id', authMiddleware(['admin', 'teacher', 'student']), async (req, res) => {
	const studIdParam = req.params.id;
	if (userSession.role === 'student' && userSession.id != studIdParam) res.sendStatus(401);

	const student = await db.getUserById(studIdParam)
	res.render('pages/student.ejs', {student: student})
});

app.get('/login', (req, res) => {
	res.render('pages/login.ejs')
});

app.post('/login', async (req, res) => {
	try {
		const { username, password } = req.body
		const passHash = await bcrypt.hash(password, 10)
		// undefined - if no record found
		userSession = await db.getUser(username)

		if (userSession === undefined) {
			failedLoginAttempt(res)
			return
		}

		const check = await bcrypt.compare(password, userSession.password);

		if (check) {
			currentKey = jwt.sign({password: password}, process.env.TOKEN, {expiresIn: 60})
			currentPassword = password

			res.method = 'GET'
			res.redirect('/start');
		} else {
			failedLoginAttempt(res)
		}
	} catch(err) {
		console.error(err)
		failedLoginAttempt(res)
	}
});

app.get('/register', async(req, res) => {
	res.render('pages/register.ejs')
});

app.post('/register', async (req, res) => {
	try {
		const username = req.body.username
		const password = req.body.password

		if (username.length < 1 || password.length < 1) {
			return res.sendStatus(400)
		}
		
		const passHash = await bcrypt.hash(password, 10)
		const resp = await db.insertUser({'username':username, 'password':passHash})

		if (resp.changes === 1) { res.redirect('/login') }
		else { res.sendStatus(500) }
	} catch(err) {
		console.error('Error while inserting a new user: ' + err);
	}
});

app.all('*', (req, res) => {
	res.sendStatus(404);
})

app.listen(8888, () => {
	db.initDB();
	console.log('Server listening on container port: ' + 8888);
});

const failedLoginAttempt = (res) => {
	res.status(401);
	res.render('pages/fail.ejs')
}

function authMiddleware(roles = []) {
	return (req, res, next) => authenticateToken(roles, req, res, next)
}

function authenticateToken(roles, req, res, next) {
	jwt.verify(currentKey, process.env.TOKEN, (err, payload) => {
		if (err) { res.redirect('/login') }
	})

	if (roles.length && roles.indexOf(userSession.role) < 0) { res.sendStatus(401) }

	next();
}