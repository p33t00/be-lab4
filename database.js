const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('users.db', err => {
	if (err) { console.error('Error connecting to DB', err); }
})

const getUser = async function(username) {
	return await __getter('SELECT * FROM users WHERE username = ? LIMIT 1;', [username])
}

const getUserById = async function(id) {
	return await __getter('SELECT * FROM users WHERE role = "student" AND id = ? LIMIT 1;', [id])
}

const getStudent = async function(id) {
	return await __getter('SELECT * FROM users WHERE role = "student" AND id = ? LIMIT 1;', [id])
}

const getAllUsers = async function() {
	return await __getterAll('SELECT * FROM users;', [])
}

const insertUser = async function(args) {
	return await __setter('INSERT INTO users (role, username, password) VALUES (?,?,?);', args);
}

const __getter = async (query, args) => {
	return await __promisify((resolve, reject) => {
		db.get(query, args, (err, data) => {
			if (err) {reject(err)} else {resolve(data)}
		})
	});
}

const __getterAll = async (query, args) => {
	return await __promisify((resolve, reject) => {
		db.all(query, args, (err, data) => {
			if (err) {reject(err)} else {resolve(data)}
		})
	});
}

const __setter = async function(query, args) {
	return await __promisify(function(resolve, reject) {
		db.run(query, args, function (err) {
			if (err) { reject(err) } else { resolve(this) }
		});
	});
}

const initDB = () => {
	db.run("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, role VARCHAR, username VARCHAR, password VARCHAR);",
        [],
        function(err) { if (err) {console.error('Error creating table users:', err);} });        
}

const __promisify = (qFunc) => new Promise(function(resolve, reject) { qFunc(resolve, reject) });


module.exports = {getUser, getAllUsers, getStudent, getUserById, insertUser, initDB}