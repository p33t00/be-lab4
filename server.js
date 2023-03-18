const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
require('dotenv').config();

const db = require('./database.js');

app.set('view-engine', 'ejs');

app.use(cookieParser());
app.use(cors({ origin: '*' }));
app.use(express.urlencoded({extended: false}));

var userSession;

app.get('/', (req, res) => {
	return res.redirect('/start');
});

app.get('/start', authMiddleware(), (req, res) => {
	res.render('pages/start.ejs');
});

app.get('/admin', authMiddleware(['admin']), async (req, res) => {
	const users = await db.getAllUsers();
	res.render('pages/admin.ejs', {users: users});
});

app.get('/teacher', authMiddleware(['admin', 'teacher']), (req, res) => {
	res.render('pages/teacher.ejs')
});

app.get('/students/:id', authMiddleware(['admin', 'teacher', 'student']), async (req, res) => {
	const studIdParam = Number(req.params.id);
	
	if (userSession.role === 'student' && userSession.id != studIdParam) return res.sendStatus(401);
	
	const student = await db.getStudent(studIdParam);

	if (!student) return res.sendStatus(404);

	res.render('pages/student.ejs', {student: student});
});

app.get('/users/:id', authMiddleware([]), async (req, res) => {
	const userIdParam = Number(req.params.id);
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
		// undefined - if no record found
		const user = await db.getUser(username)
		const check = await bcrypt.compare(password, user.password);

		if (check) {
			const token = jwt.sign(user, process.env.TOKEN)
			res.cookie('jwt', token, {httpOnly: true, maxAge: 86400000})

			res.method = 'GET'
			res.redirect('/users/'+user.id);
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
		const status = await db.insertUser([role, username, passHash])

		if (status.changes === 1) { res.redirect('/login') }
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
	jwt.verify(req.cookies.jwt, process.env.TOKEN, (err, user) => {
		console.log(user)
		if (err) { return res.redirect('/login') }
		else if (roles.length && roles.indexOf(user.role) < 0) {
			return res.sendStatus(401)
		}
		else {
			userSession = user;
			next();
		}
	})
}