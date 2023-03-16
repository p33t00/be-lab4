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


const USER_SESSION_DURATION = 1200
var currentKey = ''
var currentPassword = ''
var userSession;

app.get('/', (req, res) => {
	return res.redirect('/start');
});

app.get('/start', authMiddleware(), (req, res) => {
	res.render('pages/start.ejs', {sessionLen: USER_SESSION_DURATION});
});

app.get('/admin', authMiddleware(['admin']), async (req, res) => {
	const users = await db.getAllUsers();
	res.render('pages/admin.ejs', {users: users});
});

app.get('/teacher', authMiddleware(['admin', 'teacher']), async (req, res) => {
	res.render('pages/teacher.ejs')
});

app.get('/student/:id', authMiddleware(['admin', 'teacher', 'student']), async (req, res) => {
	const studIdParam = req.params.id;
	if (userSession.role === 'student' && userSession.id != studIdParam) return res.sendStatus(401);

	const student = await db.getStudent(studIdParam);

	if (!student) return res.sendStatus(404);

	res.render('pages/student.ejs', {student: student});
});

app.get('/users/:id', authMiddleware([]), async (req, res) => {
	const userIdParam = req.params.id;
	if (userSession.id != userIdParam) return res.sendStatus(401);

	const user = await db.getUserById(userIdParam);

	if (!user) return res.sendStatus(404);

	res.render('pages/user.ejs', {user: user});
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
			currentKey = jwt.sign({password: password}, process.env.TOKEN, {expiresIn: USER_SESSION_DURATION})
			currentPassword = password

			res.method = 'GET'
			res.redirect('/users/'+userSession.id);
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
		const role = req.body.role
		const username = req.body.username
		const password = req.body.password

		if (username.length < 1 || password.length < 1) {
			return res.sendStatus(400)
		}
		
		const passHash = await bcrypt.hash(password, 10)
		const resp = await db.insertUser([role, username, passHash])

		if (resp.changes === 1) { res.redirect('/login') }
		else { res.sendStatus(500) }
	} catch(err) {
		console.error('Error while inserting a new user: ' + err);
	}
});

app.all('*', (req, res) => {
	res.sendStatus(404);
})

app.listen(8000, () => {
	db.initDB();
	console.log('Server listening on container port: ' + 8000);
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
		if (err) { return res.redirect('/login') }
		else if (roles.length && roles.indexOf(userSession.role) < 0) { return res.sendStatus(401) }
		else { next(); }
	})
}